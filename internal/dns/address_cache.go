// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors
// Adapted from Polaris 56d52fb44958ef3cc2a7fb841cd240f8206234b2.
package dns

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

const defaultSystemLookupTTL = time.Minute

type addressCacheEntry struct {
	addresses []netip.Addr
	expires   time.Time
}

type pendingAddressLookup struct {
	done      chan struct{}
	addresses []netip.Addr
	err       error
}

type addressCache struct {
	start       func(func()) bool
	workContext func() (context.Context, context.CancelFunc)
	mu          sync.Mutex
	entries     map[string]addressCacheEntry
	pending     map[string]*pendingAddressLookup
	ttl         time.Duration
}

func newAddressCache(ttl time.Duration) *addressCache {
	if ttl <= 0 {
		ttl = defaultSystemLookupTTL
	}
	return &addressCache{
		entries: make(map[string]addressCacheEntry),
		pending: make(map[string]*pendingAddressLookup),
		ttl:     ttl,
	}
}

func (cache *addressCache) lookup(
	ctx context.Context,
	key string,
	resolve func(context.Context) ([]netip.Addr, error),
) ([]netip.Addr, error) {
	now := time.Now()
	cache.mu.Lock()
	if entry, found := cache.entries[key]; found {
		if now.Before(entry.expires) {
			addresses := cloneAddresses(entry.addresses)
			cache.mu.Unlock()
			return addresses, nil
		}
		delete(cache.entries, key)
	}
	if pending, found := cache.pending[key]; found {
		cache.mu.Unlock()
		select {
		case <-pending.done:
			return cloneAddresses(pending.addresses), pending.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if len(cache.pending) >= 128 {
		cache.mu.Unlock()
		return nil, ErrBusy
	}
	pending := &pendingAddressLookup{done: make(chan struct{})}
	cache.pending[key] = pending
	cache.mu.Unlock()

	complete := func(addresses []netip.Addr, err error) {
		cache.mu.Lock()
		delete(cache.pending, key)
		pending.addresses = cloneAddresses(addresses)
		pending.err = err
		if err == nil && len(addresses) > 0 {
			cache.evictLocked(time.Now())
			cache.entries[key] = addressCacheEntry{addresses: cloneAddresses(addresses), expires: time.Now().Add(cache.ttl)}
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
		addresses, err := resolve(workCtx)
		complete(addresses, err)
	}
	if cache.start != nil {
		if !cache.start(work) {
			complete(nil, ErrClosed)
		}
	} else {
		go work()
	}
	select {
	case <-pending.done:
		return cloneAddresses(pending.addresses), pending.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}

}

func (cache *addressCache) evictLocked(now time.Time) {
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

func cloneAddresses(addresses []netip.Addr) []netip.Addr {
	return append([]netip.Addr(nil), addresses...)
}
