// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

// Package replay contains bounded, per-server replay protection for SSR
// authentication handshakes.
package replay

import (
	"hash/maphash"
	"sync"
	"time"
)

const (
	// DefaultCapacity is large enough for sustained authenticated traffic while
	// retaining a hard memory bound. The maps are allocated lazily.
	DefaultCapacity = 1 << 20
	maxCacheShards  = 256
	entriesPerShard = 4096
)

type key struct {
	namespace string
	token     string
}

type entry struct {
	key       key
	expiresAt int64
}

// Cache rejects duplicate authenticated tokens until their TTL expires. It is
// sharded to avoid a process-wide handshake lock, fails closed when full, and
// owns no cleanup goroutine.
type Cache struct {
	now       func() time.Time
	startedAt time.Time
	seed      maphash.Seed
	shards    []cacheShard
}

type cacheShard struct {
	mu       sync.Mutex
	capacity int
	entries  map[key]int64
	expiry   []entry
}

func NewCache(now func() time.Time, capacity int) *Cache {
	if now == nil {
		now = time.Now
	}
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	shardCount := min(maxCacheShards, 1+(capacity-1)/entriesPerShard)
	cache := &Cache{
		now:       now,
		startedAt: now().Add(-30 * time.Second),
		seed:      maphash.MakeSeed(),
		shards:    make([]cacheShard, shardCount),
	}
	for index := range cache.shards {
		shardCapacity := capacity / shardCount
		if index < capacity%shardCount {
			shardCapacity++
		}
		cache.shards[index].capacity = shardCapacity
	}
	return cache
}

func (c *Cache) StartedAt() time.Time {
	if c == nil {
		return time.Time{}
	}
	return c.startedAt
}

func (c *Cache) CheckAndInsert(namespace string, token []byte, ttl time.Duration) bool {
	if c == nil || namespace == "" || len(token) == 0 || ttl <= 0 {
		return false
	}
	shard := c.shard(namespace, token)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	now := c.now().UnixNano()
	shard.sweep(now)
	// Check before converting token to string. A cache under attack remains
	// allocation-free once it reaches its fail-closed capacity.
	if len(shard.entries) >= shard.capacity {
		return false
	}
	replayKey := key{namespace: namespace, token: string(token)}
	if expiry, loaded := shard.entries[replayKey]; loaded && expiry > now {
		return false
	}
	if shard.entries == nil {
		shard.entries = make(map[key]int64, min(shard.capacity, 64))
	}
	expiresAt := now + int64(ttl)
	shard.entries[replayKey] = expiresAt
	shard.push(entry{key: replayKey, expiresAt: expiresAt})
	return true
}

func (c *Cache) shard(namespace string, token []byte) *cacheShard {
	var hash maphash.Hash
	hash.SetSeed(c.seed)
	_, _ = hash.WriteString(namespace)
	_, _ = hash.Write(token)
	return &c.shards[hash.Sum64()%uint64(len(c.shards))]
}

func (s *cacheShard) sweep(now int64) {
	for len(s.expiry) > 0 && s.expiry[0].expiresAt <= now {
		expired := s.pop()
		if deadline, loaded := s.entries[expired.key]; loaded && deadline == expired.expiresAt {
			delete(s.entries, expired.key)
		}
	}
}

func (s *cacheShard) push(value entry) {
	s.expiry = append(s.expiry, value)
	index := len(s.expiry) - 1
	for index > 0 {
		parent := (index - 1) / 2
		if s.expiry[parent].expiresAt <= value.expiresAt {
			break
		}
		s.expiry[index] = s.expiry[parent]
		index = parent
	}
	s.expiry[index] = value
}

func (s *cacheShard) pop() entry {
	result := s.expiry[0]
	last := s.expiry[len(s.expiry)-1]
	s.expiry[len(s.expiry)-1] = entry{}
	s.expiry = s.expiry[:len(s.expiry)-1]
	if len(s.expiry) == 0 {
		return result
	}
	index := 0
	for {
		left := index*2 + 1
		if left >= len(s.expiry) {
			break
		}
		right := left + 1
		child := left
		if right < len(s.expiry) && s.expiry[right].expiresAt < s.expiry[left].expiresAt {
			child = right
		}
		if s.expiry[child].expiresAt >= last.expiresAt {
			break
		}
		s.expiry[index] = s.expiry[child]
		index = child
	}
	s.expiry[index] = last
	return result
}
