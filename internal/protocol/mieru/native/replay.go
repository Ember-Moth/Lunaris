// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors
package native

import (
	"crypto/sha256"
	"github.com/Ember-Moth/Lunaris/internal/authscan"
	"time"
)

type replayCache struct {
	window *authscan.ReplayWindow[[32]byte]
}

func newReplayCache(capacity int, lifetime time.Duration) *replayCache {
	return &replayCache{window: authscan.NewReplayWindow[[32]byte](capacity, lifetime, nil)}
}

// A nonce belongs to a credential, never to a source address. Changing a UDP
// port must not renew it, and another user's nonce must not collide with it.
func (c *replayCache) seen(credential [32]byte, nonce []byte) bool {
	if c == nil || len(nonce) != nonceSize {
		return true
	}
	var input [32 + nonceSize]byte
	copy(input[:32], credential[:])
	copy(input[32:], nonce)
	return !c.window.Accept(sha256.Sum256(input[:]))
}
