// SPDX-License-Identifier: GPL-3.0-or-later

package xhttp

import (
	"io"
	"sync"
	"time"
)

const uploadCoalesceDelay = time.Millisecond

type uploadPipe struct {
	mu       sync.Mutex
	readable *sync.Cond
	writable *sync.Cond
	pool     *byteBufferPool
	buffer   *byteBuffer
	start    int
	capacity int
	closed   bool
	err      error
}

func newUploadPipe(capacity int) *uploadPipe {
	capacity = max(1, capacity)
	pipe := &uploadPipe{capacity: capacity, pool: newByteBufferPool(2 * capacity)}
	pipe.readable = sync.NewCond(&pipe.mu)
	pipe.writable = sync.NewCond(&pipe.mu)
	return pipe
}

func (pipe *uploadPipe) Write(payload []byte) (int, error) {
	pipe.mu.Lock()
	defer pipe.mu.Unlock()
	written := 0
	for len(payload) > 0 {
		for pipe.buffered() >= pipe.capacity && !pipe.closed {
			pipe.writable.Wait()
		}
		if pipe.closed {
			if pipe.err != nil {
				return written, pipe.err
			}
			return written, io.ErrClosedPipe
		}
		if pipe.buffer == nil {
			pipe.buffer = pipe.takeBuffer()
		}
		count := min(len(payload), pipe.capacity-pipe.buffered())
		if pipe.start > 0 && cap(pipe.buffer.data)-len(pipe.buffer.data) < count {
			pipe.compact()
		}
		pipe.buffer.data = append(pipe.buffer.data, payload[:count]...)
		payload = payload[count:]
		written += count
		pipe.readable.Signal()
	}
	return written, nil
}

func (pipe *uploadPipe) readChunk(limit int, coalesce time.Duration) (*byteBuffer, error) {
	pipe.mu.Lock()
	defer pipe.mu.Unlock()
	for pipe.buffered() == 0 && !pipe.closed {
		pipe.readable.Wait()
	}
	if pipe.err != nil {
		return nil, pipe.err
	}
	if pipe.buffered() == 0 {
		return nil, io.EOF
	}
	if coalesce > 0 && pipe.buffered() < limit && !pipe.closed {
		pipe.mu.Unlock()
		time.Sleep(coalesce)
		pipe.mu.Lock()
	}
	count := min(limit, pipe.buffered())
	if count == pipe.buffered() {
		if pipe.start > 0 {
			pipe.compact()
		}
		payload := pipe.buffer
		pipe.buffer = nil
		pipe.start = 0
		pipe.writable.Broadcast()
		return payload, nil
	}
	payload := pipe.pool.take(count)
	copy(payload.data, pipe.buffer.data[pipe.start:pipe.start+count])
	pipe.start += count
	pipe.writable.Broadcast()
	return payload, nil
}

func (pipe *uploadPipe) buffered() int {
	if pipe.buffer == nil {
		return 0
	}
	return len(pipe.buffer.data) - pipe.start
}

func (pipe *uploadPipe) compact() {
	copy(pipe.buffer.data, pipe.buffer.data[pipe.start:])
	pipe.buffer.data = pipe.buffer.data[:pipe.buffered()]
	pipe.start = 0
}

func (pipe *uploadPipe) takeBuffer() *byteBuffer {
	return pipe.pool.take(0)
}

func (pipe *uploadPipe) release(payload *byteBuffer) {
	if payload == nil {
		return
	}
	pipe.pool.put(payload)
}

func (pipe *uploadPipe) Close() error        { return pipe.closeWith(nil) }
func (pipe *uploadPipe) interrupt(err error) { _ = pipe.closeWith(err) }
func (pipe *uploadPipe) closeWith(err error) error {
	pipe.mu.Lock()
	defer pipe.mu.Unlock()
	if !pipe.closed {
		pipe.closed = true
		pipe.err = err
		if err != nil && pipe.buffer != nil {
			pipe.pool.put(pipe.buffer)
			pipe.buffer = nil
			pipe.start = 0
		}
		pipe.readable.Broadcast()
		pipe.writable.Broadcast()
	}
	return nil
}
