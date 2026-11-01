// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package native

import (
	"testing"
	"time"
)

func TestMetadataRoundTrip(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tests := []metadata{
		{protocol: openSessionRequest, sessionID: 7, seq: 3, status: 1, payloadLen: 512, suffixLen: 27},
		{protocol: closeSessionResponse, sessionID: 9, seq: 5, status: 0, suffixLen: 4},
		{protocol: dataClientToServer, sessionID: 11, seq: 13, unAckSeq: 12, windowSize: 4096,
			fragment: 2, prefixLen: 7, payloadLen: 1400, suffixLen: 9},
		{protocol: ackServerToClient, sessionID: 15, seq: 17, unAckSeq: 16, windowSize: 2048},
	}
	for _, expected := range tests {
		wire := expected.marshal(nil, now)
		actual, err := parseMetadata(wire, now)
		if err != nil {
			t.Fatalf("protocol %d: %v", expected.protocol, err)
		}
		if actual != expected {
			t.Fatalf("protocol %d: metadata = %+v, want %+v", expected.protocol, actual, expected)
		}
	}
}

func TestMetadataRejectsExpiredAndOversizedValues(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	value := metadata{protocol: openSessionRequest, sessionID: 1, payloadLen: maxSessionPayload}
	wire := value.marshal(nil, now.Add(-2*time.Minute))
	if _, err := parseMetadata(wire, now); err == nil {
		t.Fatal("expired metadata accepted")
	}
	wire = value.marshal(nil, now)
	wire[15], wire[16] = 0xff, 0xff
	if _, err := parseMetadata(wire, now); err == nil {
		t.Fatal("oversized session payload accepted")
	}
}
