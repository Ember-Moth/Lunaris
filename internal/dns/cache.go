// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors
// Adapted from Polaris 56d52fb44958ef3cc2a7fb841cd240f8206234b2.
package dns

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

const maxCacheEntries = 1024

type cacheKey struct {
	name  string
	qType uint16
}

type cacheEntry struct {
	response []byte
	expires  time.Time
}

// pendingExchange lets a burst of identical queries share one upstream exchange.
type pendingExchange struct {
	done chan struct{}
	// joined counts the callers sharing this exchange, so tests can wait for a
	// burst to assemble before releasing the leader.
	joined   atomic.Int32
	response []byte
	err      error
}

type cache struct {
	start       func(func()) bool
	workContext func() (context.Context, context.CancelFunc)
	mu          sync.RWMutex
	entries     map[cacheKey]cacheEntry
	pending     map[cacheKey]*pendingExchange
}

func newCache() *cache {
	return &cache{
		entries: make(map[cacheKey]cacheEntry),
		pending: make(map[cacheKey]*pendingExchange),
	}
}

// lookup returns a fresh cached response, joins an exchange already in flight for
// the same key, or runs the exchange itself.
//
// Coalescing matters here more than the entry count suggests. Routing resolves a
// name only while an IP rule could still win, and the prefer strategies issue one
// A and one AAAA query, so a popular name whose entry has just expired would send
// two queries per new connection to the same upstream. An upstream that rate-limits
// or drops that burst fails every one of those connections at once, and routing
// treats a resolve failure as soft, so they would all quietly fall back to the
// domain rules and leave through the wrong outbound.
func (cache *cache) lookup(
	ctx context.Context,
	key cacheKey,
	resolve func(context.Context) (response []byte, ttl time.Duration, err error),
) ([]byte, error) {
	if response, found := cache.get(key, time.Now()); found {
		return response, nil
	}
	cache.mu.Lock()
	// Re-check while holding the write lock: a leader may have finished between
	// the read above and here, which is the common case under a burst.
	if entry, found := cache.entries[key]; found && time.Now().Before(entry.expires) {
		response := cloneResponse(entry.response)
		cache.mu.Unlock()
		return response, nil
	}
	if pending, found := cache.pending[key]; found {
		pending.joined.Add(1)
		cache.mu.Unlock()
		select {
		case <-pending.done:
			return cloneResponse(pending.response), pending.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if len(cache.pending) >= 128 {
		cache.mu.Unlock()
		return nil, ErrBusy
	}
	pending := &pendingExchange{done: make(chan struct{})}
	cache.pending[key] = pending
	cache.mu.Unlock()

	complete := func(response []byte, ttl time.Duration, err error) {
		cache.mu.Lock()
		delete(cache.pending, key)
		pending.response = cloneResponse(response)
		pending.err = err
		if err == nil && ttl > 0 {
			cache.putLocked(key, response, time.Now().Add(ttl))
		}
		close(pending.done)
		cache.mu.Unlock()
	}
	work := func() {
		workCtx := ctx
		cancel := func() {}
		if cache.workContext != nil {
			workCtx, cancel = cache.workContext()
		}
		defer cancel()
		response, ttl, err := resolve(workCtx)
		complete(response, ttl, err)
	}
	if cache.start != nil {
		if !cache.start(work) {
			complete(nil, 0, ErrClosed)
		}
	} else {
		go work()
	}
	select {
	case <-pending.done:
		return cloneResponse(pending.response), pending.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}

}

// joined reports how many callers are sharing the exchange in flight for key.
func (cache *cache) joined(key cacheKey) int32 {
	cache.mu.RLock()
	defer cache.mu.RUnlock()
	if pending, found := cache.pending[key]; found {
		return pending.joined.Load()
	}
	return 0
}

func (cache *cache) get(key cacheKey, now time.Time) ([]byte, bool) {
	cache.mu.RLock()
	entry, found := cache.entries[key]
	cache.mu.RUnlock()
	if !found || !now.Before(entry.expires) {
		return nil, false
	}
	return cloneResponse(entry.response), true
}

func (cache *cache) put(key cacheKey, response []byte, expires time.Time) {
	cache.mu.Lock()
	cache.putLocked(key, response, expires)
	cache.mu.Unlock()
}

func (cache *cache) putLocked(key cacheKey, response []byte, expires time.Time) {
	cache.evictLocked(time.Now())
	cache.entries[key] = cacheEntry{response: cloneResponse(response), expires: expires}
}

// evictLocked clears every expired entry before falling back to dropping an
// arbitrary live one. Recency is deliberately not tracked: the read path serves
// hits under a read lock, and recording an access would have to take the write
// lock on every lookup, which costs more on the hot path than an occasional
// unlucky eviction costs at the 1024-entry ceiling.
func (cache *cache) evictLocked(now time.Time) {
	if len(cache.entries) < maxCacheEntries {
		return
	}
	for key, entry := range cache.entries {
		if !now.Before(entry.expires) {
			delete(cache.entries, key)
		}
	}
	if len(cache.entries) < maxCacheEntries {
		return
	}
	for key := range cache.entries {
		delete(cache.entries, key)
		return
	}
}

func cloneResponse(response []byte) []byte {
	if response == nil {
		return nil
	}
	return append([]byte(nil), response...)
}
