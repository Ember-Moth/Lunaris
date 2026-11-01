// Derived from XTLS/Xray-core transport/internet/splithttp/upload_queue.go at b17a88f9b46d.
// Licensed under MPL-2.0; see LICENSES/MPL-2.0/MPL-2.0.txt.

package xhttp

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// uploadStallTimeout bounds how long a post waits for buffer space while the
// reader makes no progress at all.
const uploadStallTimeout = 30 * time.Second

var (
	errUploadPostTooLarge = errors.New("xhttp: upload post exceeds the buffer limit")
	errUploadBufferStall  = errors.New("xhttp: upload buffer stalled")
)

type uploadPacket struct {
	reader   *serverStream
	payload  []byte
	owner    *byteBuffer
	sequence uint64
	reserved int64
}

type byteBudget struct {
	limit        int64
	regularLimit int64
	used         atomic.Int64
	reservations *reservationGroup
}

func newByteBudget(limit, headroom int64) *byteBudget {
	if limit <= 0 {
		return nil
	}
	headroom = min(max(headroom, 0), limit)
	budget := &byteBudget{limit: limit, regularLimit: limit - headroom}
	budget.reservations = &reservationGroup{budget: budget}
	return budget
}

// fits reports whether a payload could ever be admitted within the limit.
func (budget *byteBudget) fits(size int64, head bool) bool {
	if budget == nil {
		return true
	}
	if head {
		return size <= budget.limit
	}
	return size <= budget.regularLimit
}

func (budget *byteBudget) Used() int64 {
	if budget == nil {
		return 0
	}
	return budget.used.Load()
}

type reservationWaiter struct {
	queue    *uploadQueue
	sequence uint64
	size     int64
	ready    chan struct{}
	granted  bool
	prev     *reservationWaiter
	next     *reservationWaiter
}

var reservationWaiterPool = sync.Pool{New: func() any {
	return &reservationWaiter{ready: make(chan struct{}, 1)}
}}

// reservationGroup serializes the byte counters shared by one or more upload
// queues and grants capacity directly to eligible waiters. Releases therefore
// wake only requests that are guaranteed to make progress instead of closing a
// generation channel and waking every blocked HTTP handler.
type reservationGroup struct {
	mu     sync.Mutex
	budget *byteBudget
	head   *reservationWaiter
	tail   *reservationWaiter
}

func (group *reservationGroup) enqueueLocked(waiter *reservationWaiter) {
	if group.tail == nil {
		group.head = waiter
	} else {
		group.tail.next = waiter
		waiter.prev = group.tail
	}
	group.tail = waiter
}

func (group *reservationGroup) removeLocked(waiter *reservationWaiter) {
	if waiter.prev == nil {
		group.head = waiter.next
	} else {
		waiter.prev.next = waiter.next
	}
	if waiter.next == nil {
		group.tail = waiter.prev
	} else {
		waiter.next.prev = waiter.prev
	}
	waiter.prev = nil
	waiter.next = nil
}

func (group *reservationGroup) wakeLocked() {
	for waiter := group.head; waiter != nil; {
		next := waiter.next
		if waiter.queue.reserveLocked(waiter.size, waiter.queue.isHead(waiter.sequence)) {
			group.removeLocked(waiter)
			waiter.granted = true
			waiter.ready <- struct{}{}
		}
		waiter = next
	}
}

func recycleReservationWaiter(waiter *reservationWaiter) {
	select {
	case <-waiter.ready:
	default:
	}
	*waiter = reservationWaiter{ready: waiter.ready}
	reservationWaiterPool.Put(waiter)
}

type uploadQueue struct {
	mu        sync.Mutex
	reader    *serverStream
	packets   chan uploadPacket
	ring      []uploadPacket
	occupied  []bool
	ringCount int
	current   []byte
	owned     uploadPacket
	next      atomic.Uint64
	max       int
	maxSize   int
	maxBytes  int64

	queuedBytes  atomic.Int64
	budget       *byteBudget
	reservations *reservationGroup

	done       chan struct{}
	close      sync.Once
	closeErr   error
	pushMu     sync.Mutex
	pushClosed bool
	pushes     sync.WaitGroup
	readMu     sync.Mutex
	pool       *byteBufferPool
}

// advanceNext moves to the next expected sequence. Waiters are notified because a
// post that was out of order may now be the one the reader is blocked on, which
// makes it exempt from the buffer limits.
func (queue *uploadQueue) advanceNext() {
	queue.next.Add(1)
	queue.reservations.mu.Lock()
	queue.reservations.wakeLocked()
	queue.reservations.mu.Unlock()
}

func (queue *uploadQueue) isHead(sequence uint64) bool {
	return queue.next.Load() == sequence
}

func newUploadQueue(
	maxPackets, maxPacketSize int,
	maxQueuedBytes int64,
	budget *byteBudget,
	pool *byteBufferPool,
) *uploadQueue {
	reservations := &reservationGroup{}
	if budget != nil {
		reservations = budget.reservations
	}
	return &uploadQueue{
		packets: make(chan uploadPacket, maxPackets),
		max:     maxPackets, maxSize: maxPacketSize, maxBytes: maxQueuedBytes, budget: budget,
		done: make(chan struct{}), pool: pool, reservations: reservations,
	}
}

// ensureReassembly allocates the out-of-order reassembly window on first use.
// Stream-up sessions and strictly in-order uploads never reach this path, so
// the per-session window is not allocated for the common case.
func (queue *uploadQueue) ensureReassembly() {
	if queue.ring == nil {
		queue.ring = make([]uploadPacket, queue.max)
		queue.occupied = make([]bool, queue.max)
	}
}

func (queue *uploadQueue) push(ctx context.Context, packet uploadPacket) error {
	queue.pushMu.Lock()
	if queue.pushClosed {
		queue.pushMu.Unlock()
		queue.releaseReservation(packet.reserved)
		return io.ErrClosedPipe
	}
	queue.pushes.Add(1)
	queue.pushMu.Unlock()
	defer queue.pushes.Done()

	if packet.reader != nil {
		queue.mu.Lock()
		if queue.reader != nil {
			queue.mu.Unlock()
			return errors.New("xhttp: upload reader already exists")
		}
		queue.reader = packet.reader
		queue.mu.Unlock()
	}
	if packet.reserved != 0 && packet.reserved != int64(len(packet.payload)) {
		queue.releaseReservation(packet.reserved)
		return errors.New("xhttp: invalid upload reservation")
	}
	if packet.reserved == 0 {
		packet.reserved = int64(len(packet.payload))
		if err := queue.awaitReservation(ctx, packet.sequence, packet.reserved); err != nil {
			packet.reserved = 0
			return err
		}
	}
	select {
	case queue.packets <- packet:
		return nil
	case <-queue.done:
		queue.releaseReservation(packet.reserved)
		return io.ErrClosedPipe
	case <-ctx.Done():
		queue.releaseReservation(packet.reserved)
		return ctx.Err()
	}
}

func (queue *uploadQueue) Close() error {
	queue.close.Do(func() {
		queue.pushMu.Lock()
		queue.pushClosed = true
		close(queue.done)
		queue.pushMu.Unlock()
		queue.pushes.Wait()

		queue.mu.Lock()
		reader := queue.reader
		queue.mu.Unlock()
		if reader != nil {
			queue.closeErr = reader.Close()
		}
		queue.readMu.Lock()
		queue.releaseAll()
		queue.readMu.Unlock()
	})
	return queue.closeErr
}

func (queue *uploadQueue) Read(output []byte) (int, error) {
	queue.readMu.Lock()
	defer queue.readMu.Unlock()

	queue.mu.Lock()
	reader := queue.reader
	queue.mu.Unlock()
	if reader != nil {
		return reader.Read(output)
	}
	select {
	case <-queue.done:
		return 0, io.EOF
	default:
	}
	for {
		if len(queue.current) > 0 {
			n := copy(output, queue.current)
			queue.current = queue.current[n:]
			if len(queue.current) == 0 {
				queue.releasePacket(queue.owned)
				queue.owned = uploadPacket{}
				queue.advanceNext()
			}
			return n, nil
		}
		if packet, loaded := queue.takeNext(); loaded {
			queue.current, queue.owned = packet.payload, packet
			if len(queue.current) == 0 {
				queue.releasePacket(queue.owned)
				queue.owned = uploadPacket{}
				queue.advanceNext()
			}
			continue
		}

		var packet uploadPacket
		select {
		case packet = <-queue.packets:
			if packet.reader != nil {
				return packet.reader.Read(output)
			}
		case <-queue.done:
			return 0, io.EOF
		}
		if packet.sequence < queue.next.Load() {
			queue.releasePacket(packet)
			continue
		}
		if packet.sequence == queue.next.Load() {
			queue.current, queue.owned = packet.payload, packet
			if len(queue.current) == 0 {
				queue.releasePacket(queue.owned)
				queue.owned = uploadPacket{}
				queue.advanceNext()
			}
			continue
		}
		if packet.sequence-queue.next.Load() >= uint64(queue.max) || queue.ringCount >= queue.max {
			queue.releasePacket(packet)
			return 0, errors.New("xhttp: upload reassembly queue is too large")
		}
		queue.ensureReassembly()
		index := int(packet.sequence % uint64(queue.max))
		if queue.occupied[index] {
			queue.releasePacket(packet)
			if queue.ring[index].sequence == packet.sequence {
				continue
			}
			return 0, errors.New("xhttp: upload reassembly window collision")
		}
		queue.ring[index] = packet
		queue.occupied[index] = true
		queue.ringCount++
	}
}

func (queue *uploadQueue) takeNext() (uploadPacket, bool) {
	if queue.ring == nil {
		return uploadPacket{}, false
	}
	next := queue.next.Load()
	index := int(next % uint64(queue.max))
	if !queue.occupied[index] || queue.ring[index].sequence != next {
		return uploadPacket{}, false
	}
	packet := queue.ring[index]
	queue.ring[index] = uploadPacket{}
	queue.occupied[index] = false
	queue.ringCount--
	return packet, true
}

// awaitReservation waits for buffer space instead of rejecting the post. A full
// buffer means the reader is behind, and failing the request tears down the whole
// session; holding the handler keeps the HTTP stream open so the peer's flow
// control slows the sender.
//
// Both the per-session and shared budgets keep one maximum-sized packet of
// headroom. A head-of-line post may use that headroom but never exceed the hard
// limit, preventing later sequences from starving the packet that unlocks them.
func (queue *uploadQueue) awaitReservation(ctx context.Context, sequence uint64, size int64) error {
	if size == 0 {
		return nil
	}
	if queue.maxSize > 0 && size > int64(queue.maxSize) {
		return errUploadPostTooLarge
	}
	if !queue.fits(size, true) || !queue.budget.fits(size, true) {
		return errUploadPostTooLarge
	}
	group := queue.reservations
	group.mu.Lock()
	if queue.reserveLocked(size, queue.isHead(sequence)) {
		group.mu.Unlock()
		return nil
	}
	waiter := reservationWaiterPool.Get().(*reservationWaiter)
	waiter.queue = queue
	waiter.sequence = sequence
	waiter.size = size
	group.enqueueLocked(waiter)
	group.mu.Unlock()

	timer := time.NewTimer(uploadStallTimeout)
	defer timer.Stop()
	select {
	case <-waiter.ready:
		recycleReservationWaiter(waiter)
		return nil
	case <-queue.done:
		queue.cancelReservationWaiter(waiter)
		return io.ErrClosedPipe
	case <-ctx.Done():
		queue.cancelReservationWaiter(waiter)
		return ctx.Err()
	case <-timer.C:
		queue.cancelReservationWaiter(waiter)
		return errUploadBufferStall
	}
}

func (queue *uploadQueue) cancelReservationWaiter(waiter *reservationWaiter) {
	group := queue.reservations
	group.mu.Lock()
	if waiter.granted {
		queue.releaseReservationLocked(waiter.size)
	} else {
		group.removeLocked(waiter)
	}
	group.wakeLocked()
	group.mu.Unlock()
	recycleReservationWaiter(waiter)
}

func (queue *uploadQueue) reservePacket(ctx context.Context, sequence uint64, size int64) (uploadPacket, error) {
	if err := queue.awaitReservation(ctx, sequence, size); err != nil {
		return uploadPacket{}, err
	}
	return uploadPacket{sequence: sequence, reserved: size}, nil
}

func (queue *uploadQueue) shrinkReservation(packet *uploadPacket, size int64) {
	if size >= packet.reserved {
		return
	}
	queue.releaseReservation(packet.reserved - size)
	packet.reserved = size
}

func (queue *uploadQueue) fits(size int64, head bool) bool {
	if queue.maxBytes <= 0 {
		return true
	}
	limit := queue.maxBytes - min(int64(queue.maxSize), queue.maxBytes)
	if head {
		limit = queue.maxBytes
	}
	return size <= limit
}

func (queue *uploadQueue) reserveLocked(size int64, head bool) bool {
	if size == 0 {
		return true
	}
	limit := queue.maxBytes - min(int64(queue.maxSize), queue.maxBytes)
	if head {
		limit = queue.maxBytes
	}
	if queue.maxBytes > 0 && queue.queuedBytes.Load()+size > limit {
		return false
	}
	if queue.budget != nil {
		budgetLimit := queue.budget.regularLimit
		if head {
			budgetLimit = queue.budget.limit
		}
		if queue.budget.used.Load()+size > budgetLimit {
			return false
		}
		queue.budget.used.Add(size)
	}
	queue.queuedBytes.Add(size)
	return true
}

func (queue *uploadQueue) releaseReservation(size int64) {
	if size == 0 {
		return
	}
	group := queue.reservations
	group.mu.Lock()
	queue.releaseReservationLocked(size)
	group.wakeLocked()
	group.mu.Unlock()
}

func (queue *uploadQueue) releaseReservationLocked(size int64) {
	queue.queuedBytes.Add(-size)
	if queue.budget != nil {
		queue.budget.used.Add(-size)
	}
}

func (queue *uploadQueue) releasePacket(packet uploadPacket) {
	queue.releaseReservation(packet.reserved)
	queue.releasePayload(packet.owner)
}

func (queue *uploadQueue) releaseAll() {
	if queue.owned.payload != nil || queue.owned.owner != nil {
		queue.releasePacket(queue.owned)
		queue.owned = uploadPacket{}
		queue.current = nil
	}
	for index, occupied := range queue.occupied {
		if !occupied {
			continue
		}
		queue.releasePacket(queue.ring[index])
		queue.ring[index] = uploadPacket{}
		queue.occupied[index] = false
	}
	queue.ringCount = 0
	for {
		select {
		case packet := <-queue.packets:
			queue.releasePacket(packet)
		default:
			return
		}
	}
}

func (queue *uploadQueue) takePayload(size int) *byteBuffer {
	return queue.pool.take(size)
}

func (queue *uploadQueue) releasePayload(payload *byteBuffer) {
	if payload == nil {
		return
	}
	queue.pool.put(payload)
}
