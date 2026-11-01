// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package native

import (
	"net"
	"testing"
	"time"
)

func TestReplayCacheSeparatesPacketSources(t *testing.T) {
	cache := newReplayCache(4, time.Minute)
	nonce := make([]byte, nonceSize)
	first := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1}
	second := &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 1}
	if cache.seen(nonce, first) || !cache.seen(nonce, first) {
		t.Fatal("same-source replay was not detected")
	}
	if cache.seen(nonce, second) {
		t.Fatal("different packet source was treated as replay")
	}
}

func TestReplayCacheEvictsAtCapacity(t *testing.T) {
	cache := newReplayCache(2, time.Minute)
	for value := byte(1); value <= 3; value++ {
		nonce := make([]byte, nonceSize)
		nonce[0] = value
		if cache.seen(nonce, nil) {
			t.Fatal("fresh nonce treated as replay")
		}
	}
	first := make([]byte, nonceSize)
	first[0] = 1
	if cache.seen(first, nil) {
		t.Fatal("oldest nonce was not evicted")
	}
}
