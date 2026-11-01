// SPDX-License-Identifier: GPL-3.0-or-later

package xhttp

import "sync"

// byteBufferPool recycles variable-size byte slices through a sync.Pool so idle
// buffers are reclaimed by the garbage collector instead of being pinned for
// the process lifetime. XHTTP posts are far larger than sing's 72 KiB pooled
// ceiling, so this keeps XHTTP's own recycling while letting the runtime drop
// the retained set under memory pressure. Buffers larger than maxCapacity are
// not retained.
type byteBuffer struct {
	data []byte
}

type byteBufferPool struct {
	pool        sync.Pool
	maxCapacity int
}

func newByteBufferPool(maxCapacity int) *byteBufferPool {
	pool := &byteBufferPool{maxCapacity: max(1, maxCapacity)}
	pool.pool.New = func() any { return new(byteBuffer) }
	return pool
}

func (pool *byteBufferPool) take(size int) *byteBuffer {
	buffer := pool.pool.Get().(*byteBuffer)
	if cap(buffer.data) < size {
		// Replacing a small backing array lets the GC reclaim it while keeping
		// the heap-resident slice header for reuse.
		buffer.data = make([]byte, size)
	} else {
		buffer.data = buffer.data[:size]
	}
	return buffer
}

func (pool *byteBufferPool) put(buffer *byteBuffer) {
	if buffer == nil {
		return
	}
	if cap(buffer.data) > pool.maxCapacity {
		buffer.data = nil
	} else {
		buffer.data = buffer.data[:0]
	}
	pool.pool.Put(buffer)
}
