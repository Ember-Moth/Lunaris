// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package replay

import (
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCapacityFailsClosedAndExpiryReopens(t *testing.T) {
	now := time.Unix(100, 0)
	cache := NewCache(func() time.Time { return now }, 2)
	if !cache.CheckAndInsert("auth", []byte("first"), time.Minute) ||
		!cache.CheckAndInsert("auth", []byte("second"), time.Second) {
		t.Fatal("initial insert failed")
	}
	if cache.CheckAndInsert("auth", []byte("third"), time.Minute) {
		t.Fatal("full cache accepted token")
	}
	now = now.Add(2 * time.Second)
	if !cache.CheckAndInsert("auth", []byte("third"), time.Minute) {
		t.Fatal("expired capacity was not reclaimed")
	}
	if cache.CheckAndInsert("auth", []byte("third"), time.Minute) {
		t.Fatal("replay was accepted")
	}
}

func TestNamespacesAreIndependent(t *testing.T) {
	cache := NewCache(nil, 4)
	if !cache.CheckAndInsert("protocol", []byte("token"), time.Minute) ||
		!cache.CheckAndInsert("obfs", []byte("token"), time.Minute) {
		t.Fatal("namespace collision")
	}
}

func TestDefaultCapacityHandlesMoreThanLegacyLimit(t *testing.T) {
	cache := NewCache(nil, DefaultCapacity)
	var token [8]byte
	for index := range 8192 {
		binary.LittleEndian.PutUint64(token[:], uint64(index))
		if !cache.CheckAndInsert("authenticated-handshake", token[:], 24*time.Hour) {
			t.Fatalf("fresh token %d rejected", index)
		}
	}
}

func TestConcurrentDuplicateIsAcceptedOnce(t *testing.T) {
	cache := NewCache(nil, 64)
	var accepted atomic.Int32
	var workers sync.WaitGroup
	for range 64 {
		workers.Go(func() {
			if cache.CheckAndInsert("auth", []byte("same-token"), time.Minute) {
				accepted.Add(1)
			}
		})
	}
	workers.Wait()
	if count := accepted.Load(); count != 1 {
		t.Fatalf("duplicate token accepted %d times, want 1", count)
	}
}

func BenchmarkFullMiss(b *testing.B) {
	for _, capacity := range []int{64, 1024, 4096} {
		b.Run(fmt.Sprint(capacity), func(b *testing.B) {
			now := time.Unix(1000, 0)
			cache := NewCache(func() time.Time { return now }, capacity)
			var token [8]byte
			for index := range capacity {
				binary.LittleEndian.PutUint64(token[:], uint64(index))
				if !cache.CheckAndInsert("benchmark", token[:], time.Hour) {
					b.Fatal("fill failed")
				}
			}
			b.ReportAllocs()
			for b.Loop() {
				if cache.CheckAndInsert("benchmark", []byte("miss"), time.Hour) {
					b.Fatal("full cache accepted token")
				}
			}
		})
	}
}
