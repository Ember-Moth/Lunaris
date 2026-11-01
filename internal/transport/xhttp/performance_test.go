// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package xhttp

import (
	"context"
	"testing"
)

func BenchmarkUploadQueueReadPacket(b *testing.B) {
	const packetSize = 1024 * 1024
	queue := newUploadQueue(1, packetSize, packetSize, nil, newByteBufferPool(2*packetSize))
	output := make([]byte, 32*1024)
	b.SetBytes(packetSize)
	b.ReportAllocs()
	b.ResetTimer()
	for index := range b.N {
		owner := queue.takePayload(packetSize)
		if err := queue.push(context.Background(), uploadPacket{payload: owner.data, owner: owner, sequence: uint64(index)}); err != nil {
			b.Fatal(err)
		}
		for offset := 0; offset < packetSize; offset += len(output) {
			if _, err := queue.Read(output); err != nil {
				b.Fatal(err)
			}
		}
	}
}

func BenchmarkUploadPipeFullChunk(b *testing.B) {
	const packetSize = 1024 * 1024
	pipe := newUploadPipe(packetSize)
	payload := make([]byte, packetSize)
	b.SetBytes(packetSize)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := pipe.Write(payload); err != nil {
			b.Fatal(err)
		}
		chunk, err := pipe.readChunk(packetSize, 0)
		if err != nil {
			b.Fatal(err)
		}
		pipe.release(chunk)
	}
}

func BenchmarkUploadReservationWake(b *testing.B) {
	queue := newUploadQueue(1, 1, 1, nil, newByteBufferPool(1))
	queue.reservations.mu.Lock()
	if !queue.reserveLocked(1, true) {
		b.Fatal("initial reservation failed")
	}
	queue.reservations.mu.Unlock()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		waiter := reservationWaiterPool.Get().(*reservationWaiter)
		waiter.queue, waiter.sequence, waiter.size = queue, 0, 1
		queue.reservations.mu.Lock()
		queue.reservations.enqueueLocked(waiter)
		queue.reservations.mu.Unlock()
		queue.releaseReservation(1)
		<-waiter.ready
		recycleReservationWaiter(waiter)
	}
}

func BenchmarkXMUXGetDefault(b *testing.B) {
	manager := newXMUXManager(XMUXConfig{MaxConnections: Range{From: 3, To: 3}}, func() xmuxConn { return new(fakeXMUXConn) })
	defer func() { _ = manager.Close() }()
	for range 3 {
		_ = manager.get()
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = manager.get()
	}
}

func BenchmarkXMUXGetWithConcurrency(b *testing.B) {
	manager := newXMUXManager(XMUXConfig{MaxConcurrency: Range{From: 100, To: 100}}, func() xmuxConn { return new(fakeXMUXConn) })
	defer func() { _ = manager.Close() }()
	_ = manager.get()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = manager.get()
	}
}
