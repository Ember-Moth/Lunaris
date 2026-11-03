// SPDX-License-Identifier: GPL-3.0-only
package authscan

import (
	"sync"
	"time"
)

// ReplayWindow retains accepted identities for a fixed lifetime. It rejects
// new entries at capacity instead of evicting still-valid replay protection.
// Entries expire in insertion order; no timer goroutine or periodic full scan
// is needed. The caller supplies a credential-separated key.
type ReplayWindow[K comparable] struct {
	mu       sync.Mutex
	now      func() time.Time
	lifetime time.Duration
	capacity int
	entries  map[K]struct{}
	queue    []replayRecord[K]
	head     int
	size     int
}
type replayRecord[K comparable] struct {
	key     K
	expires time.Time
}

func NewReplayWindow[K comparable](capacity int, lifetime time.Duration, now func() time.Time) *ReplayWindow[K] {
	if capacity < 1 || lifetime <= 0 {
		panic("invalid replay window")
	}
	if now == nil {
		now = time.Now
	}
	return &ReplayWindow[K]{capacity: capacity, lifetime: lifetime, now: now}
}
func (w *ReplayWindow[K]) Accept(key K) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.now()
	for w.size > 0 && !now.Before(w.queue[w.head].expires) {
		delete(w.entries, w.queue[w.head].key)
		var empty replayRecord[K]
		w.queue[w.head] = empty
		w.head = (w.head + 1) % w.capacity
		w.size--
	}
	if _, exists := w.entries[key]; exists {
		return false
	}
	if w.size >= w.capacity {
		return false
	}
	if w.entries == nil {
		w.entries = make(map[K]struct{})
		w.queue = make([]replayRecord[K], w.capacity)
	}
	w.entries[key] = struct{}{}
	w.queue[(w.head+w.size)%w.capacity] = replayRecord[K]{key: key, expires: now.Add(w.lifetime)}
	w.size++
	return true
}
