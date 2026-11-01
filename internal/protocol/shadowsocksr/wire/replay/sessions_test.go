// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package replay

import (
	"testing"
	"time"
)

func TestSessionsLimitIsPerUser(t *testing.T) {
	now := time.Unix(1000, 0)
	sessions := NewSessions(func() time.Time { return now })
	first := [4]byte{1}
	second := [4]byte{2}
	for client := range uint32(2) {
		if !sessions.Accept(first, client, 1, 2) || !sessions.Accept(second, client, 1, 2) {
			t.Fatal("client was rejected before per-user limit")
		}
	}
	if sessions.Accept(first, 3, 1, 2) {
		t.Fatal("per-user client limit was not enforced")
	}
	if sessions.Accept(first, 1, 1, 2) {
		t.Fatal("connection replay was accepted")
	}
	if !sessions.Accept(first, 1, 2, 2) {
		t.Fatal("next connection was rejected")
	}
}

func TestSessionsExpiryReclaimsClient(t *testing.T) {
	now := time.Unix(1000, 0)
	sessions := NewSessions(func() time.Time { return now })
	user := [4]byte{1}
	if !sessions.Accept(user, 1, 1, 1) {
		t.Fatal("initial client rejected")
	}
	sessions.Release(user, 1)
	now = now.Add(clientIdleTimeout + time.Second)
	if !sessions.Accept(user, 2, 1, 1) {
		t.Fatal("expired client capacity was not reclaimed")
	}
}

func TestSessionsReleaseImmediatelyReclaimsActiveLimit(t *testing.T) {
	sessions := NewSessions(nil)
	user := [4]byte{1}
	if !sessions.Accept(user, 1, 1, 1) {
		t.Fatal("initial client rejected")
	}
	if sessions.Accept(user, 2, 1, 1) {
		t.Fatal("second active client exceeded limit")
	}
	sessions.Release(user, 1)
	if !sessions.Accept(user, 2, 1, 1) {
		t.Fatal("closed client continued to consume active limit")
	}
	if sessions.Accept(user, 1, 1, 1) {
		t.Fatal("released client's replay history was lost")
	}
}

func TestSessionsReleaseCountsConcurrentConnections(t *testing.T) {
	sessions := NewSessions(nil)
	user := [4]byte{1}
	if !sessions.Accept(user, 1, 1, 1) || !sessions.Accept(user, 1, 2, 1) {
		t.Fatal("same active client was rejected")
	}
	sessions.Release(user, 1)
	if sessions.Accept(user, 2, 1, 1) {
		t.Fatal("client limit was released while one connection remained")
	}
	sessions.Release(user, 1)
	if !sessions.Accept(user, 2, 1, 1) {
		t.Fatal("final connection release did not reclaim client limit")
	}
}

func TestSessionsConnectionWindowIncludesBoundary(t *testing.T) {
	sessions := NewSessions(nil)
	user := [4]byte{1}
	for connectionID := uint32(1); connectionID <= connectionWindowSize; connectionID++ {
		if !sessions.Accept(user, 1, connectionID, 1) {
			t.Fatalf("connection %d rejected before window filled", connectionID)
		}
		sessions.Release(user, 1)
	}
	if !sessions.Accept(user, 1, connectionWindowSize+1, 1) {
		t.Fatal("connection at the sliding-window boundary was rejected")
	}
	if sessions.Accept(user, 1, 1, 1) {
		t.Fatal("evicted connection ID was accepted as an in-window replay")
	}
}
