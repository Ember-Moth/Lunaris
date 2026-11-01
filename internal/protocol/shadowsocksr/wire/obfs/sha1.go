// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package obfs

import (
	"crypto/sha1"
	"crypto/subtle"
	"hash"
)

// sha1HMAC reuses the digest and fixed-size pads used by the authenticated
// legacy TLS obfuscations. Each stream owns one worker.
type sha1HMAC struct {
	digest   hash.Hash
	innerPad [sha1.BlockSize]byte
	outerPad [sha1.BlockSize]byte
	inner    [sha1.Size]byte
	output   [sha1.Size]byte
}

func newSHA1HMAC() *sha1HMAC {
	return &sha1HMAC{digest: sha1.New()}
}

func (m *sha1HMAC) sum(keyFirst, keySecond, dataFirst, dataSecond []byte) []byte {
	keyLength := len(keyFirst) + len(keySecond)
	if keyLength > len(m.innerPad) {
		m.digest.Reset()
		_, _ = m.digest.Write(keyFirst)
		_, _ = m.digest.Write(keySecond)
		keyFirst = m.digest.Sum(m.inner[:0])
		keySecond = nil
		keyLength = len(keyFirst)
	}
	for index := range m.innerPad {
		var value byte
		switch {
		case index < len(keyFirst):
			value = keyFirst[index]
		case index < keyLength:
			value = keySecond[index-len(keyFirst)]
		}
		m.innerPad[index] = value ^ 0x36
		m.outerPad[index] = value ^ 0x5c
	}
	m.digest.Reset()
	_, _ = m.digest.Write(m.innerPad[:])
	_, _ = m.digest.Write(dataFirst)
	_, _ = m.digest.Write(dataSecond)
	inner := m.digest.Sum(m.inner[:0])
	m.digest.Reset()
	_, _ = m.digest.Write(m.outerPad[:])
	_, _ = m.digest.Write(inner)
	return m.digest.Sum(m.output[:0])
}

func validSHA1(sum, expected []byte) bool {
	return len(sum) >= len(expected) && subtle.ConstantTimeCompare(sum[:len(expected)], expected) == 1
}
