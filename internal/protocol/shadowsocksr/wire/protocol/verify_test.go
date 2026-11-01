// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package protocol

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/protocol/shadowsocksr/wire/replay"
)

func TestVerifyFixedVectorsAndSplits(t *testing.T) {
	vectors := []struct {
		name string
		wire string
	}{
		{name: "verify_simple", wire: "000e01017f0000010050e6c3b72e000e01017f0000010050e6c3b72e"},
		{name: "verify_sha1", wire: "117f000001005012f706fccef6d41c9dd800078bd2880b3a2a6ca5f3df017f0000010050"},
	}
	want := bytes.Repeat([]byte{1, 127, 0, 0, 1, 0, 80}, 2)
	for _, vector := range vectors {
		t.Run(vector.name, func(t *testing.T) {
			wire, err := hex.DecodeString(vector.wire)
			if err != nil {
				t.Fatal(err)
			}
			definition, err := New(Config{Name: vector.name, ServerKey: []byte("fixed-server-key"), SingleUserID: [4]byte{1}})
			if err != nil {
				t.Fatal(err)
			}
			for split := 0; split <= len(wire); split++ {
				stream := definition.NewStream(nil)
				stream.SetReadIV([]byte("fixed-iv-1234567"))
				first, _, _, err := stream.Decode(nil, wire[:split])
				if err != nil {
					t.Fatalf("split %d first: %v", split, err)
				}
				second, _, _, err := stream.Decode(nil, wire[split:])
				if err != nil {
					t.Fatalf("split %d second: %v", split, err)
				}
				if actual := append(first, second...); !bytes.Equal(actual, want) {
					t.Fatalf("split %d output = %x", split, actual)
				}
				if userID, authenticated := stream.UserID(); !authenticated || userID != [4]byte{1} {
					t.Fatalf("split %d user = %v, %v", split, userID, authenticated)
				}
				stream.Close()
			}
		})
	}
}

func TestLegacyAuthFixedVectorsAndSplits(t *testing.T) {
	vectors := []struct {
		name   string
		header string
		frame  string
	}{
		{name: "auth_simple", header: "001a0100f153650102030407000000017f00000100501e8e6f93", frame: "000e01017f0000010050e6c3b72e"},
		{name: "auth_sha1", header: "b10d748800240100f153650102030407000000017f000001005078de36618a223dd99471", frame: "000e01017f0000010050e100e403"},
		{name: "auth_sha1_v2", header: "9a98d1780026ff0003010203040506070807000000017f00000100500c1b41c25e0f3ed2ed95", frame: "000e01017f0000010050e100e403"},
		{name: "auth_sha1_v4", header: "002454181fde0100f153650102030407000000017f0000010050e2e84558f23bf7ffa085", frame: "00109b0201017f00000100508001380a"},
	}
	want := bytes.Repeat([]byte{1, 127, 0, 0, 1, 0, 80}, 2)
	now := time.Unix(1700000000, 0)
	for _, vector := range vectors {
		t.Run(vector.name, func(t *testing.T) {
			header, _ := hex.DecodeString(vector.header)
			frame, _ := hex.DecodeString(vector.frame)
			wire := append(header, frame...)
			for split := 0; split <= len(wire); split++ {
				definition, err := New(Config{Name: vector.name, ServerKey: []byte("fixed-server-key"),
					SingleUserID: [4]byte{1}, Now: func() time.Time { return now },
					Replay: replay.NewCache(func() time.Time { return now }, 32)})
				if err != nil {
					t.Fatal(err)
				}
				stream := definition.NewStream(nil)
				stream.SetReadIV([]byte("fixed-iv-1234567"))
				first, _, firstReply, err := stream.Decode(nil, wire[:split])
				if err != nil {
					t.Fatalf("split %d first: %v", split, err)
				}
				second, _, secondReply, err := stream.Decode(nil, wire[split:])
				if err != nil {
					t.Fatalf("split %d second: %v", split, err)
				}
				if actual := append(first, second...); !bytes.Equal(actual, want) {
					t.Fatalf("split %d output = %x", split, actual)
				}
				if userID, authenticated := stream.UserID(); !authenticated || userID != [4]byte{1} {
					t.Fatalf("split %d user = %v, %v", split, userID, authenticated)
				}
				expectsReply := vector.name == "auth_sha1_v2" || vector.name == "auth_sha1_v4"
				if (firstReply || secondReply) != expectsReply {
					t.Fatalf("split %d reply = %v/%v", split, firstReply, secondReply)
				}
				stream.Close()
			}
		})
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	for _, vector := range []struct{ name, wire string }{
		{name: "verify_simple", wire: "000e01017f0000010050e6c3b72e"},
		{name: "verify_sha1", wire: "117f000001005012f706fccef6d41c9dd8"},
	} {
		wire, _ := hex.DecodeString(vector.wire)
		wire[len(wire)-1] ^= 0x80
		definition, _ := New(Config{Name: vector.name, ServerKey: []byte("fixed-server-key"), SingleUserID: [4]byte{1}})
		stream := definition.NewStream(nil)
		stream.SetReadIV([]byte("fixed-iv-1234567"))
		if decoded, _, _, err := stream.Decode(nil, wire); err == nil || len(decoded) != 0 {
			t.Fatalf("%s decoded=%x error=%v", vector.name, decoded, err)
		}
		stream.Close()
	}
}
