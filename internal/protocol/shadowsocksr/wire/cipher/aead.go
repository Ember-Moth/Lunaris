// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package cipher

import (
	"crypto/aes"
	stdcipher "crypto/cipher"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	aeadTagSize       = 16
	aeadLengthSize    = 2
	aeadLengthBoxSize = aeadLengthSize + aeadTagSize
	maxAEADPayload    = 0x3fff
	subkeyInfo        = "ss-subkey"
)

var (
	ErrAuthentication = errors.New("shadowsocksr: cipher authentication failed")
	ErrRecordTooLarge = errors.New("shadowsocksr: invalid SIP004 record length")
	ErrReplay         = errors.New("shadowsocksr: cipher salt replay")
)

type aeadFactory func(key []byte) (stdcipher.AEAD, error)

func aeadMethodSpec(method string) (keyLen int, factory aeadFactory, loaded bool) {
	switch method {
	case "aes-128-gcm":
		return 16, aesGCM, true
	case "aes-192-gcm":
		return 24, aesGCM, true
	case "aes-256-gcm":
		return 32, aesGCM, true
	case "chacha20-ietf-poly1305":
		return chacha20poly1305.KeySize, chacha20poly1305.New, true
	case "xchacha20-ietf-poly1305":
		return chacha20poly1305.KeySize, chacha20poly1305.NewX, true
	default:
		return 0, nil, false
	}
}

func aesGCM(key []byte) (stdcipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return stdcipher.NewGCM(block)
}

func (s *Suite) newAEAD(salt []byte) (stdcipher.AEAD, error) {
	if !s.IsAEAD() {
		return nil, fmt.Errorf("%w: %q is a stream cipher", ErrCipherMode, s.name)
	}
	if len(salt) != s.ivLen {
		return nil, fmt.Errorf("shadowsocksr: cipher salt length %d, want %d", len(salt), s.ivLen)
	}
	var subkey [32]byte
	deriveSubkey(s.key, salt, subkey[:len(s.key)])
	aead, err := s.aead(subkey[:len(s.key)])
	clear(subkey[:])
	return aead, err
}

// deriveSubkey is the fixed-shape HKDF-SHA1 used by SIP004. All supported
// methods derive 16, 24, or 32 bytes from an equally sized master key and salt,
// so two stack-backed HMAC expansion blocks replace the allocation-heavy
// generic HKDF reader on the per-packet path.
func deriveSubkey(key, salt, output []byte) {
	prk := fixedHMACSHA1(salt, key, nil, 0, false)
	first := fixedHMACSHA1(prk[:], nil, []byte(subkeyInfo), 1, true)
	copied := copy(output, first[:])
	if copied < len(output) {
		second := fixedHMACSHA1(prk[:], first[:], []byte(subkeyInfo), 2, true)
		copy(output[copied:], second[:])
	}
}

func fixedHMACSHA1(key, first, second []byte, suffix byte, hasSuffix bool) [sha1.Size]byte {
	var inner [sha1.BlockSize + 64]byte
	var outer [sha1.BlockSize + sha1.Size]byte
	for index := range sha1.BlockSize {
		var value byte
		if index < len(key) {
			value = key[index]
		}
		inner[index] = value ^ 0x36
		outer[index] = value ^ 0x5c
	}
	offset := sha1.BlockSize
	offset += copy(inner[offset:], first)
	offset += copy(inner[offset:], second)
	if hasSuffix {
		inner[offset] = suffix
		offset++
	}
	innerDigest := sha1.Sum(inner[:offset])
	copy(outer[sha1.BlockSize:], innerDigest[:])
	return sha1.Sum(outer[:])
}

// AEADStream encodes and incrementally decodes one SIP004 TCP stream. It is
// stateful and must not be shared between connections or directions.
type AEADStream struct {
	aead          stdcipher.AEAD
	nonce         []byte
	pending       []byte
	payloadLength int
	lengthBuffer  [aeadLengthSize]byte
	authenticated bool
	failed        bool
}

func (s *Suite) NewAEADStream(salt []byte) (*AEADStream, error) {
	aead, err := s.newAEAD(salt)
	if err != nil {
		return nil, err
	}
	return &AEADStream{aead: aead, nonce: make([]byte, aead.NonceSize()), payloadLength: -1}, nil
}

// Seal appends one or more SIP004 records to dst. Payloads larger than the
// protocol limit are split without changing application-visible boundaries.
func (s *AEADStream) Seal(dst, plaintext []byte) ([]byte, error) {
	if s.failed {
		return nil, ErrAuthentication
	}
	for len(plaintext) > 0 {
		chunkSize := min(len(plaintext), maxAEADPayload)
		binary.BigEndian.PutUint16(s.lengthBuffer[:], uint16(chunkSize))
		dst = s.aead.Seal(dst, s.nonce, s.lengthBuffer[:], nil)
		incrementNonce(s.nonce)
		dst = s.aead.Seal(dst, s.nonce, plaintext[:chunkSize], nil)
		incrementNonce(s.nonce)
		plaintext = plaintext[chunkSize:]
	}
	return dst, nil
}

// Open appends every complete plaintext record in input to dst. Incomplete
// tails are retained internally, so callers may pass arbitrary TCP fragments.
func (s *AEADStream) Open(dst, input []byte) ([]byte, error) {
	if s.failed {
		return nil, ErrAuthentication
	}
	for {
		if s.payloadLength < 0 {
			box, buffered, complete := s.nextBox(&input, aeadLengthBoxSize)
			if !complete {
				return dst, nil
			}
			if _, err := s.aead.Open(s.lengthBuffer[:0], s.nonce, box, nil); err != nil {
				return nil, s.fail(err)
			}
			if buffered {
				s.pending = s.pending[:0]
			}
			incrementNonce(s.nonce)
			s.payloadLength = int(binary.BigEndian.Uint16(s.lengthBuffer[:]))
			if s.payloadLength > maxAEADPayload {
				return nil, s.fail(ErrRecordTooLarge)
			}
		}

		payloadBoxSize := s.payloadLength + s.aead.Overhead()
		box, buffered, complete := s.nextBox(&input, payloadBoxSize)
		if !complete {
			return dst, nil
		}
		var err error
		dst, err = s.aead.Open(dst, s.nonce, box, nil)
		if err != nil {
			return nil, s.fail(err)
		}
		if buffered {
			s.pending = s.pending[:0]
		}
		incrementNonce(s.nonce)
		s.authenticated = true
		s.payloadLength = -1
		if len(input) == 0 {
			return dst, nil
		}
	}
}

// nextBox returns exactly size contiguous bytes while retaining at most one
// partial record. A large coalesced input is never copied merely because its
// first record completed a previously fragmented box.
func (s *AEADStream) nextBox(input *[]byte, size int) (box []byte, buffered, complete bool) {
	if len(s.pending) == 0 && len(*input) >= size {
		box = (*input)[:size]
		*input = (*input)[size:]
		return box, false, true
	}
	needed := size - len(s.pending)
	consumed := min(needed, len(*input))
	s.pending = append(s.pending, (*input)[:consumed]...)
	*input = (*input)[consumed:]
	if len(s.pending) != size {
		return nil, true, false
	}
	return s.pending, true, true
}

func (s *AEADStream) fail(cause error) error {
	s.failed = true
	clear(s.nonce)
	clear(s.pending)
	clear(s.lengthBuffer[:])
	s.pending = nil
	return fmt.Errorf("%w: %w", ErrAuthentication, cause)
}

// Authenticated reports whether at least one complete record authenticated.
func (s *AEADStream) Authenticated() bool { return s.authenticated }

// Pending reports whether a partial encrypted record remains buffered.
func (s *AEADStream) Pending() bool { return len(s.pending) != 0 || s.payloadLength >= 0 }

func (s *AEADStream) Close() {
	clear(s.nonce)
	clear(s.pending)
	clear(s.lengthBuffer[:])
	s.aead = nil
	s.nonce = nil
	s.pending = nil
	s.failed = true
}

func incrementNonce(nonce []byte) {
	for index := range nonce {
		nonce[index]++
		if nonce[index] != 0 {
			return
		}
	}
}
