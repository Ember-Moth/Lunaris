// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package native

import (
	"crypto/sha256"
	"net"
	"sync"
	"time"
)

type replayEntry struct {
	key  [16]byte
	seen int64
}

type replayCache struct {
	mu       sync.Mutex
	entries  map[[16]byte]int64
	ring     []replayEntry
	next     int
	lifetime int64
}

func newReplayCache(capacity int, lifetime time.Duration) *replayCache {
	return &replayCache{entries: make(map[[16]byte]int64, capacity), ring: make([]replayEntry, capacity), lifetime: int64(lifetime)}
}

func (c *replayCache) seen(nonce []byte, source net.Addr) bool {
	if c == nil || len(nonce) < nonceSize {
		return true
	}
	hash := sha256.New()
	_, _ = hash.Write(nonce[:nonceSize])
	if source != nil {
		_, _ = hash.Write([]byte(source.String()))
	}
	sum := hash.Sum(nil)
	var key [16]byte
	copy(key[:], sum[:16])
	now := time.Now().UnixNano()
	c.mu.Lock()
	defer c.mu.Unlock()
	if previous, exists := c.entries[key]; exists && now-previous < c.lifetime {
		return true
	}
	old := c.ring[c.next]
	if old.seen != 0 {
		if current, exists := c.entries[old.key]; exists && current == old.seen {
			delete(c.entries, old.key)
		}
	}
	c.entries[key] = now
	c.ring[c.next] = replayEntry{key: key, seen: now}
	c.next++
	if c.next == len(c.ring) {
		c.next = 0
	}
	return false
}
