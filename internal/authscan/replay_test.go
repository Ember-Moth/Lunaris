// SPDX-License-Identifier: GPL-3.0-only
package authscan

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestReplayWindowRetainsEntriesAtCapacityAndExpires(t *testing.T) {
	now := time.Unix(100, 0)
	window := NewReplayWindow[int](2, time.Minute, func() time.Time { return now })
	if !window.Accept(1) || !window.Accept(2) {
		t.Fatal("fresh identities rejected")
	}
	if window.Accept(3) || window.Accept(1) {
		t.Fatal("capacity evicted live replay protection")
	}
	now = now.Add(time.Minute - time.Nanosecond)
	if window.Accept(1) {
		t.Fatal("entry expired early")
	}
	now = now.Add(time.Nanosecond)
	if !window.Accept(3) || !window.Accept(1) || window.Accept(1) {
		t.Fatal("expiry did not reclaim bounded entries")
	}
}
func TestReplayWindowConcurrentDuplicateOnlyAcceptedOnce(t *testing.T) {
	window := NewReplayWindow[int](4, time.Minute, nil)
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if window.Accept(1) {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatal("duplicate reservations", accepted.Load())
	}
}
