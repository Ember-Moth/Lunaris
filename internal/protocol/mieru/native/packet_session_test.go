// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package native

import (
	"math"
	"testing"
	"time"
)

func TestPacketCumulativeAckAcrossSequenceWrap(t *testing.T) {
	now := time.Now()
	session := &packetSession{
		inflight: map[uint32]*packetOutbound{
			math.MaxUint32 - 1: {sentAt: now, timeout: time.Second, attempts: 1},
			math.MaxUint32:     {sentAt: now, timeout: time.Second, attempts: 1},
			0:                  {sentAt: now, timeout: time.Second, attempts: 1},
		},
		oldestSend: math.MaxUint32 - 1,
		nextRetry:  now.Add(time.Second),
		cwnd:       16,
	}
	session.accept(segment{meta: metadata{protocol: ackClientToServer, unAckSeq: 1}})
	if len(session.inflight) != 0 || session.oldestSend != 1 || !session.nextRetry.IsZero() {
		t.Fatalf("cumulative ACK left state: inflight=%d oldest=%d retry=%v",
			len(session.inflight), session.oldestSend, session.nextRetry)
	}
}

func TestPacketCumulativeAckStopsAtUnacknowledgedSequence(t *testing.T) {
	now := time.Now()
	session := &packetSession{
		inflight: map[uint32]*packetOutbound{
			5: {sentAt: now, timeout: time.Second, attempts: 1},
			6: {sentAt: now, timeout: 2 * time.Second, attempts: 1},
		},
		oldestSend: 5,
		nextRetry:  now.Add(time.Second),
		cwnd:       16,
	}
	session.accept(segment{meta: metadata{protocol: ackClientToServer, unAckSeq: 6}})
	if _, exists := session.inflight[5]; exists {
		t.Fatal("acknowledged sequence remains in flight")
	}
	if _, exists := session.inflight[6]; !exists || session.oldestSend != 6 {
		t.Fatal("unacknowledged sequence was removed")
	}
	if want := now.Add(2 * time.Second); !session.nextRetry.Equal(want) {
		t.Fatalf("next retry = %v, want %v", session.nextRetry, want)
	}
}
