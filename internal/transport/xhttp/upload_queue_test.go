// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package xhttp

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

// A full upload buffer must slow the peer down rather than fail the request and
// tear the session down.
func TestUploadQueueAppliesBackpressureInsteadOfFailing(t *testing.T) {
	queue := newUploadQueue(4, 4, 8, nil, newByteBufferPool(2048))
	defer func() { _ = queue.Close() }()
	if err := queue.push(context.Background(), uploadPacket{payload: []byte("1234"), sequence: 0}); err != nil {
		t.Fatal(err)
	}
	blocked := make(chan error, 1)
	go func() {
		blocked <- queue.push(context.Background(), uploadPacket{payload: []byte("5678"), sequence: 2})
	}()
	select {
	case err := <-blocked:
		t.Fatalf("push returned %v instead of waiting for buffer space", err)
	case <-time.After(100 * time.Millisecond):
	}
	output := make([]byte, 4)
	if _, err := io.ReadFull(queue, output); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-blocked:
		if err != nil {
			t.Fatalf("push after drain: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("push did not resume after the reader drained the buffer")
	}
}

// The regression that makes blocking backpressure safe at all: out-of-order posts
// hold the whole buffer while the reader waits for an earlier sequence. That
// sequence must still be admitted, or the session deadlocks.
func TestUploadQueueAdmitsHeadOfLineWhenBufferIsFull(t *testing.T) {
	queue := newUploadQueue(4, 4, 8, newByteBudget(8, 4), newByteBufferPool(2048))
	defer func() { _ = queue.Close() }()
	// Sequence 1 arrives first and consumes the entire per-session buffer and the
	// entire shared budget, while the reader needs sequence 0.
	if err := queue.push(context.Background(), uploadPacket{payload: []byte("SCND"), sequence: 1}); err != nil {
		t.Fatal(err)
	}
	admitted := make(chan error, 1)
	go func() {
		admitted <- queue.push(context.Background(), uploadPacket{payload: []byte("FRST"), sequence: 0})
	}()
	select {
	case err := <-admitted:
		if err != nil {
			t.Fatalf("head-of-line post rejected: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("head-of-line post was starved by the out-of-order post holding the buffer")
	}
	if used := queue.budget.Used(); used != 8 {
		t.Fatalf("shared budget with headroom = %d, want hard limit 8", used)
	}
	output := make([]byte, 8)
	if _, err := io.ReadFull(queue, output); err != nil {
		t.Fatal(err)
	}
	if string(output) != "FRSTSCND" {
		t.Fatalf("reassembled = %q, want FRSTSCND", output)
	}
	if used := queue.queuedBytes.Load(); used != 0 {
		t.Fatalf("queued bytes after drain = %d", used)
	}
	if used := queue.budget.Used(); used != 0 {
		t.Fatalf("shared budget after drain = %d", used)
	}
}

// A post that becomes the head while it waits must be released, not left to the
// stall timeout.
func TestUploadQueueAdmitsPostThatBecomesHeadWhileWaiting(t *testing.T) {
	queue := newUploadQueue(4, 4, 12, nil, newByteBufferPool(2048))
	defer func() { _ = queue.Close() }()
	if err := queue.push(context.Background(), uploadPacket{payload: []byte("AAAA"), sequence: 0}); err != nil {
		t.Fatal(err)
	}
	if err := queue.push(context.Background(), uploadPacket{payload: []byte("BBBB"), sequence: 1}); err != nil {
		t.Fatal(err)
	}
	// The buffer is full and sequence 2 is not the head yet.
	waiting := make(chan error, 1)
	go func() {
		waiting <- queue.push(context.Background(), uploadPacket{payload: []byte("CCCC"), sequence: 2})
	}()
	select {
	case err := <-waiting:
		t.Fatalf("push returned %v instead of waiting", err)
	case <-time.After(100 * time.Millisecond):
	}
	output := make([]byte, 8)
	if _, err := io.ReadFull(queue, output); err != nil {
		t.Fatal(err)
	}
	if string(output) != "AAAABBBB" {
		t.Fatalf("payload = %q, want AAAABBBB", output)
	}
	select {
	case err := <-waiting:
		if err != nil {
			t.Fatalf("push after becoming head: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("push was not released once its sequence became the head")
	}
}

func TestUploadQueueReservationGrantsOnlyEligibleWaiters(t *testing.T) {
	queue := newUploadQueue(4, 4, 8, nil, newByteBufferPool(8))
	defer func() { _ = queue.Close() }()
	if err := queue.push(context.Background(), uploadPacket{payload: []byte("AAAA"), sequence: 0}); err != nil {
		t.Fatal(err)
	}
	first := make(chan error, 1)
	go func() {
		first <- queue.push(context.Background(), uploadPacket{payload: []byte("BBBB"), sequence: 1})
	}()
	waitReservationCount(t, queue.reservations, 1)
	second := make(chan error, 1)
	go func() {
		second <- queue.push(context.Background(), uploadPacket{payload: []byte("C"), sequence: 2})
	}()
	waitReservationCount(t, queue.reservations, 2)

	output := make([]byte, 4)
	if _, err := io.ReadFull(queue, output); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-first:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("new head waiter was not granted")
	}
	select {
	case err := <-second:
		t.Fatalf("ineligible waiter was woken early: %v", err)
	case <-time.After(25 * time.Millisecond):
	}

	if _, err := io.ReadFull(queue, output); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-second:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("second waiter was not granted after capacity advanced")
	}
}

func TestUploadQueueReservationCancellationDoesNotLeakCapacity(t *testing.T) {
	for range 100 {
		queue := newUploadQueue(1, 1, 1, nil, newByteBufferPool(1))
		queue.reservations.mu.Lock()
		if !queue.reserveLocked(1, true) {
			queue.reservations.mu.Unlock()
			t.Fatal("initial reservation failed")
		}
		queue.reservations.mu.Unlock()

		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() { result <- queue.awaitReservation(ctx, 0, 1) }()
		waitReservationCount(t, queue.reservations, 1)

		go cancel()
		queue.releaseReservation(1)
		err := <-result
		if err == nil {
			queue.releaseReservation(1)
		} else if !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected reservation error: %v", err)
		}
		if used := queue.queuedBytes.Load(); used != 0 {
			t.Fatalf("reservation capacity leaked: %d", used)
		}
		_ = queue.Close()
	}
}

func waitReservationCount(t *testing.T, group *reservationGroup, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		group.mu.Lock()
		count := 0
		for waiter := group.head; waiter != nil; waiter = waiter.next {
			count++
		}
		group.mu.Unlock()
		if count == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("reservation waiters did not reach %d", want)
}

// A non-head post larger than the buffer can never be admitted, so it must fail at
// once instead of waiting out the stall timeout.
func TestUploadQueueRejectsOversizedNonHeadPost(t *testing.T) {
	queue := newUploadQueue(4, 4, 8, newByteBudget(64, 4), newByteBufferPool(2048))
	defer func() { _ = queue.Close() }()
	done := make(chan error, 1)
	go func() {
		done <- queue.push(context.Background(), uploadPacket{payload: []byte("123456"), sequence: 3})
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("oversized post was accepted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("oversized post waited instead of failing fast")
	}
}

func TestUploadQueueCloseUnblocksPush(t *testing.T) {
	queue := newUploadQueue(4, 4, 8, nil, newByteBufferPool(2048))
	if err := queue.push(context.Background(), uploadPacket{payload: []byte("1234"), sequence: 0}); err != nil {
		t.Fatal(err)
	}
	blocked := make(chan error, 1)
	go func() {
		blocked <- queue.push(context.Background(), uploadPacket{payload: []byte("5678"), sequence: 2})
	}()
	time.Sleep(50 * time.Millisecond)
	_ = queue.Close()
	select {
	case err := <-blocked:
		if err == nil {
			t.Fatal("push succeeded on a closed queue")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("push did not wake when the queue closed")
	}
}

func TestUploadQueueReordersAndPreservesRemainder(t *testing.T) {
	queue := newUploadQueue(4, 1024, 4096, nil, newByteBufferPool(2048))
	defer func() { _ = queue.Close() }()
	for _, packet := range []uploadPacket{
		{payload: []byte("cd"), sequence: 1},
		{payload: []byte("ab"), sequence: 0},
		{payload: []byte("ef"), sequence: 2},
	} {
		if err := queue.push(context.Background(), packet); err != nil {
			t.Fatal(err)
		}
	}
	output := make([]byte, 6)
	for offset := 0; offset < len(output); {
		n, err := queue.Read(output[offset : offset+1])
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			t.Fatal("zero-length read without an error")
		}
		offset += n
	}
	if string(output) != "abcdef" {
		t.Fatalf("payload = %q", output)
	}
}

func TestUploadQueueCloseUnblocksRead(t *testing.T) {
	queue := newUploadQueue(1, 1024, 1024, nil, newByteBufferPool(2048))
	result := make(chan error, 1)
	go func() {
		_, err := queue.Read(make([]byte, 1))
		result <- err
	}()
	_ = queue.Close()
	if err := <-result; !errors.Is(err, io.EOF) {
		t.Fatalf("read error = %v, want EOF", err)
	}
}

func TestUploadQueueRejectsSequenceOutsideRingWindow(t *testing.T) {
	queue := newUploadQueue(4, 1024, 4096, nil, newByteBufferPool(2048))
	defer func() { _ = queue.Close() }()
	if err := queue.push(context.Background(), uploadPacket{payload: []byte("far"), sequence: 4}); err != nil {
		t.Fatal(err)
	}
	if _, err := queue.Read(make([]byte, 3)); err == nil {
		t.Fatal("expected out-of-window sequence error")
	}
	if used := queue.queuedBytes.Load(); used != 0 {
		t.Fatalf("queued bytes after rejection = %d", used)
	}
}

func TestUploadQueueByteBudgetIsSharedAndReleased(t *testing.T) {
	budget := newByteBudget(5, 4)
	pool := newByteBufferPool(2048)
	first := newUploadQueue(4, 4, 8, budget, pool)
	defer func() { _ = first.Close() }()
	second := newUploadQueue(4, 4, 8, budget, pool)
	defer func() { _ = second.Close() }()
	if err := first.push(context.Background(), uploadPacket{payload: []byte("1234"), sequence: 0}); err != nil {
		t.Fatal(err)
	}
	// A full buffer holds an out-of-order post until space appears rather than
	// failing it, so a caller that will not wait needs a deadline of its own.
	blocked, cancelBlocked := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelBlocked()
	if err := first.push(blocked, uploadPacket{payload: []byte("x"), sequence: 1}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("per-session backpressure error = %v, want deadline exceeded", err)
	}
	shared, cancelShared := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelShared()
	if err := second.push(shared, uploadPacket{payload: []byte("12"), sequence: 1}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shared backpressure error = %v, want deadline exceeded", err)
	}
	output := make([]byte, 4)
	if _, err := io.ReadFull(first, output); err != nil {
		t.Fatal(err)
	}
	if used := budget.Used(); used != 0 {
		t.Fatalf("shared budget after read = %d", used)
	}
	if err := second.push(context.Background(), uploadPacket{payload: []byte("12"), sequence: 0}); err != nil {
		t.Fatalf("push after release: %v", err)
	}
	if err := second.Close(); err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if used := budget.Used(); used != 0 {
		t.Fatalf("shared budget after close = %d", used)
	}
}

func TestUploadQueueDefersReassemblyRingUntilOutOfOrder(t *testing.T) {
	queue := newUploadQueue(4, 1024, 4096, nil, newByteBufferPool(2048))
	defer func() { _ = queue.Close() }()

	// In-order delivery must never allocate the reassembly window.
	if err := queue.push(context.Background(), uploadPacket{payload: []byte("abc"), sequence: 0}); err != nil {
		t.Fatal(err)
	}
	inOrder := make([]byte, 3)
	if _, err := io.ReadFull(queue, inOrder); err != nil {
		t.Fatal(err)
	}
	if queue.ring != nil {
		t.Fatal("in-order upload allocated the reassembly ring")
	}

	// Out-of-order delivery (seq 2 before seq 1) must allocate it on demand and
	// still reassemble correctly. Both packets are queued before reading so the
	// read completes synchronously.
	if err := queue.push(context.Background(), uploadPacket{payload: []byte("Y"), sequence: 2}); err != nil {
		t.Fatal(err)
	}
	if err := queue.push(context.Background(), uploadPacket{payload: []byte("X"), sequence: 1}); err != nil {
		t.Fatal(err)
	}
	reassembled := make([]byte, 2)
	if _, err := io.ReadFull(queue, reassembled); err != nil {
		t.Fatal(err)
	}
	if string(reassembled) != "XY" {
		t.Fatalf("reassembled = %q, want XY", reassembled)
	}
	if queue.ring == nil {
		t.Fatal("out-of-order upload did not allocate the reassembly ring")
	}
}
