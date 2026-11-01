// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package xhttp

import (
	"runtime"
	"testing"
)

func TestByteBufferPoolRecyclesWithinGeneration(t *testing.T) {
	pool := newByteBufferPool(4096)
	first := pool.take(64)
	for index := range first.data {
		first.data[index] = 0xAB
	}
	pool.put(first)
	reused := pool.take(64)
	if len(reused.data) != 64 {
		t.Fatalf("reused length = %d, want 64", len(reused.data))
	}
	pool.put(reused)
}

func TestByteBufferPoolDropsBuffersLargerThanMax(t *testing.T) {
	pool := newByteBufferPool(64)
	pool.put(&byteBuffer{data: make([]byte, 0, 4096)})
	// An oversized buffer must not be retained; the next take must allocate.
	got := pool.take(4096)
	if cap(got.data) != 4096 {
		t.Fatalf("take(4096) cap = %d, want a fresh 4096 allocation", cap(got.data))
	}
}

// TestByteBufferPoolReleasedByGC pins the memory fix: retained buffers must be
// reclaimable by the garbage collector rather than held for the process
// lifetime. The previous slice-stack pool failed this because it never
// released its backing slices; a sync.Pool clears its contents across two GC
// cycles, so a take afterward observes a fresh, zeroed allocation.
func TestByteBufferPoolReleasedByGC(t *testing.T) {
	pool := newByteBufferPool(4096)
	buffer := pool.take(64)
	for index := range buffer.data {
		buffer.data[index] = 0xAB
	}
	pool.put(buffer)

	runtime.GC()
	runtime.GC()

	fresh := pool.take(64)
	for index, value := range fresh.data {
		if value != 0 {
			t.Fatalf("byte %d = %#x after GC; pool pinned a buffer instead of releasing it", index, value)
		}
	}
}
