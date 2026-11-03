// SPDX-License-Identifier: GPL-3.0-or-later
// Adapted from Polaris 56d52fb44958ef3cc2a7fb841cd240f8206234b2.
// Copyright (C) 2026 Polaris contributors.
package authscan

import (
	"testing"
	"time"
)

func TestGuardBoundsWorkAndPenalizesFailures(t *testing.T) {
	now := time.Unix(100, 0)
	guard := NewGuard[int](func(value int) uint64 { return uint64(value) }, GuardOptions{
		WorkRate: 10, WorkBurst: 10, Concurrent: 1, TimeFunc: func() time.Time { return now },
	})
	permit, allowed := guard.Acquire(1, 6)
	if !allowed {
		t.Fatal("initial scan was rejected")
	}
	if _, allowed = guard.Acquire(2, 1); allowed {
		t.Fatal("concurrent scan bypassed the slot limit")
	}
	permit.Done(false)
	if _, allowed = guard.Acquire(1, 1); allowed {
		t.Fatal("failed source bypassed backoff")
	}
	if _, allowed = guard.Acquire(2, 5); allowed {
		t.Fatal("work budget was exceeded")
	}
	now = now.Add(time.Second)
	permit, allowed = guard.Acquire(1, 5)
	if !allowed {
		t.Fatal("refilled scan was rejected")
	}
	permit.Done(true)
	permit, allowed = guard.Acquire(1, 5)
	if !allowed {
		t.Fatal("successful source remained penalized")
	}
	permit.Done(true)
}

func TestGuardBoundsFailureEntries(t *testing.T) {
	now := time.Unix(100, 0)
	guard := NewGuard[int](func(int) uint64 { return 0 }, GuardOptions{
		WorkRate: 1 << 20, WorkBurst: 1 << 20, Concurrent: 1, TimeFunc: func() time.Time { return now },
	})
	for key := 0; key < entriesPerShard*2; key++ {
		permit, allowed := guard.Acquire(key, 1)
		if !allowed {
			t.Fatalf("scan %d was rejected", key)
		}
		permit.Done(false)
	}
	if entries := len(guard.shards[0].entries); entries != entriesPerShard {
		t.Fatalf("entries = %d, want %d", entries, entriesPerShard)
	}
}
