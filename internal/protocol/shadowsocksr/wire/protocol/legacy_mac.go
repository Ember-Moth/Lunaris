// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package protocol

import (
	"crypto/subtle"
	"encoding/binary"
	"hash"
)

// legacyMAC reuses one digest for the short HMACs used by the legacy SSR
// protocols. A Stream owns its instance; packet definitions lend instances
// from a sync.Pool. This avoids rebuilding two digest objects for every frame.
//
// MD5 and SHA-1 both use a 64-byte compression block and have digests no
// larger than 20 bytes.
type legacyMAC struct {
	digest   hash.Hash
	innerPad [64]byte
	outerPad [64]byte
	inner    [20]byte
	output   [20]byte
	sequence [4]byte
}

func newLegacyMAC(factory func() hash.Hash) *legacyMAC {
	digest := factory()
	return &legacyMAC{digest: digest}
}

func (m *legacyMAC) sum(key, data []byte) []byte {
	return m.sumParts(key, nil, false, data)
}

func (m *legacyMAC) sumJoined(first, second, data []byte) []byte {
	return m.sumParts(first, second, false, data)
}

func (m *legacyMAC) sumSequence(key []byte, sequence uint32, data []byte) []byte {
	binary.LittleEndian.PutUint32(m.sequence[:], sequence)
	return m.sumParts(key, nil, true, data)
}

func (m *legacyMAC) sumParts(first, second []byte, withSequence bool, data []byte) []byte {
	keyLength := len(first) + len(second)
	if withSequence {
		keyLength += len(m.sequence)
	}
	if keyLength > len(m.innerPad) {
		m.digest.Reset()
		_, _ = m.digest.Write(first)
		_, _ = m.digest.Write(second)
		if withSequence {
			_, _ = m.digest.Write(m.sequence[:])
		}
		first = m.digest.Sum(m.inner[:0])
		second = nil
		withSequence = false
		keyLength = len(first)
	}
	for index := range m.innerPad {
		var value byte
		switch {
		case index < len(first):
			value = first[index]
		case index < len(first)+len(second):
			value = second[index-len(first)]
		case withSequence && index < keyLength:
			value = m.sequence[index-len(first)-len(second)]
		}
		m.innerPad[index] = value ^ 0x36
		m.outerPad[index] = value ^ 0x5c
	}
	m.digest.Reset()
	_, _ = m.digest.Write(m.innerPad[:])
	_, _ = m.digest.Write(data)
	inner := m.digest.Sum(m.inner[:0])
	m.digest.Reset()
	_, _ = m.digest.Write(m.outerPad[:])
	_, _ = m.digest.Write(inner)
	return m.digest.Sum(m.output[:0])
}

func (m *legacyMAC) digestParts(first, second []byte) []byte {
	m.digest.Reset()
	_, _ = m.digest.Write(first)
	_, _ = m.digest.Write(second)
	return m.digest.Sum(m.output[:0])
}

func validLegacyMAC(sum, expected []byte, length int) bool {
	return len(sum) >= length && len(expected) == length && subtle.ConstantTimeCompare(sum[:length], expected) == 1
}
