// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package native

import (
	"encoding/base64"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

func TestTrafficPatternExplicitValues(t *testing.T) {
	var nonce []byte
	nonce = protowire.AppendTag(nonce, 1, protowire.VarintType)
	nonce = protowire.AppendVarint(nonce, 3)
	nonce = protowire.AppendTag(nonce, 2, protowire.VarintType)
	nonce = protowire.AppendVarint(nonce, 1)
	nonce = protowire.AppendTag(nonce, 3, protowire.VarintType)
	nonce = protowire.AppendVarint(nonce, 2)
	nonce = protowire.AppendTag(nonce, 4, protowire.VarintType)
	nonce = protowire.AppendVarint(nonce, 4)
	nonce = protowire.AppendTag(nonce, 5, protowire.BytesType)
	nonce = protowire.AppendString(nonce, "001122")
	var padding []byte
	padding = protowire.AppendTag(padding, 1, protowire.VarintType)
	padding = protowire.AppendVarint(padding, 7)
	padding = protowire.AppendTag(padding, 2, protowire.VarintType)
	padding = protowire.AppendVarint(padding, 11)
	var raw []byte
	raw = protowire.AppendTag(raw, 4, protowire.BytesType)
	raw = protowire.AppendBytes(raw, nonce)
	raw = protowire.AppendTag(raw, 5, protowire.BytesType)
	raw = protowire.AppendBytes(raw, padding)
	pattern, err := decodeTrafficPattern(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	if pattern.nonce.kind != 3 || !pattern.nonce.applyAll || pattern.nonce.minLen != 2 || pattern.nonce.maxLen != 4 ||
		len(pattern.nonce.fixed) != 1 || pattern.middlePad != 7 || pattern.endPad != 11 {
		t.Fatalf("unexpected pattern: %+v", pattern)
	}
	value := make([]byte, nonceSize)
	pattern.rewriteNonce(value)
	if value[0] != 0 || value[1] != 0x11 || value[2] != 0x22 {
		t.Fatalf("fixed nonce prefix = %x", value[:3])
	}
}

func TestTrafficPatternRejectsInvalidLimits(t *testing.T) {
	var padding []byte
	padding = protowire.AppendTag(padding, 1, protowire.VarintType)
	padding = protowire.AppendVarint(padding, 256)
	var raw []byte
	raw = protowire.AppendTag(raw, 5, protowire.BytesType)
	raw = protowire.AppendBytes(raw, padding)
	if err := ValidateTrafficPattern(base64.StdEncoding.EncodeToString(raw)); err == nil {
		t.Fatal("oversized padding accepted")
	}
	if err := ValidateTrafficPattern("%%%invalid%%%"); err == nil {
		t.Fatal("invalid base64 accepted")
	}
}

func TestTrafficPatternMalformedInputNeverPanics(t *testing.T) {
	for length := 1; length < 128; length++ {
		raw := make([]byte, length)
		for index := range raw {
			raw[index] = byte(index*31 + length)
		}
		_ = ValidateTrafficPattern(base64.StdEncoding.EncodeToString(raw))
	}
}
