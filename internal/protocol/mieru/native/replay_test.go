// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors
package native

import (
	"testing"
	"time"
)

func TestReplayCacheSeparatesCredentials(t *testing.T) {
	cache := newReplayCache(4, time.Minute)
	nonce := make([]byte, nonceSize)
	first, second := [32]byte{1}, [32]byte{2}
	if cache.seen(first, nonce) || !cache.seen(first, nonce) {
		t.Fatal("credential replay not rejected")
	}
	if cache.seen(second, nonce) {
		t.Fatal("another credential's nonce collided")
	}
}
func TestReplayCacheRejectsCapacityWithoutEvictingProtection(t *testing.T) {
	cache := newReplayCache(2, time.Minute)
	credential := [32]byte{1}
	for value := byte(1); value <= 2; value++ {
		nonce := make([]byte, nonceSize)
		nonce[0] = value
		if cache.seen(credential, nonce) {
			t.Fatal("fresh nonce rejected")
		}
	}
	third := make([]byte, nonceSize)
	third[0] = 3
	if !cache.seen(credential, third) {
		t.Fatal("over-capacity insertion accepted")
	}
	first := make([]byte, nonceSize)
	first[0] = 1
	if !cache.seen(credential, first) {
		t.Fatal("still-live replay record evicted")
	}
}
