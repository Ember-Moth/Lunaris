// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package cipher

import (
	"bytes"
	"crypto/aes"
	stdcipher "crypto/cipher"
	"crypto/hkdf"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

var sip004Methods = []string{
	"aes-128-gcm",
	"aes-192-gcm",
	"aes-256-gcm",
	"chacha20-ietf-poly1305",
	"xchacha20-ietf-poly1305",
}

func TestSIP004PacketMatchesReference(t *testing.T) {
	for _, method := range sip004Methods {
		t.Run(method, func(t *testing.T) {
			suite, err := NewSuite(method, "server-password")
			if err != nil {
				t.Fatal(err)
			}
			salt := testSalt(suite.IVLen())
			plaintext := bytes.Repeat([]byte("sip004-packet"), 37)
			wire, err := suite.SealPacket(nil, plaintext, salt)
			if err != nil {
				t.Fatal(err)
			}
			aead := referenceAEAD(t, method, "server-password", salt)
			expected := append([]byte(nil), salt...)
			expected = aead.Seal(expected, make([]byte, aead.NonceSize()), plaintext, nil)
			if !bytes.Equal(wire, expected) {
				t.Fatal("packet wire differs from the SIP004 reference")
			}
			if got := len(wire) - len(plaintext); got != suite.PacketOverhead() {
				t.Fatalf("packet overhead = %d, want %d", got, suite.PacketOverhead())
			}
		})
	}
}

func TestSIP004StreamMatchesReferenceAndArbitraryFragments(t *testing.T) {
	payload := make([]byte, maxAEADPayload*2+911)
	for index := range payload {
		payload[index] = byte(index*31 + 7)
	}
	for _, method := range sip004Methods {
		t.Run(method, func(t *testing.T) {
			suite, err := NewSuite(method, "server-password")
			if err != nil {
				t.Fatal(err)
			}
			salt := testSalt(suite.IVLen())
			encoder, err := suite.NewAEADStream(salt)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := encoder.Seal(nil, payload)
			if err != nil {
				t.Fatal(err)
			}
			expected := referenceSealStream(t, method, "server-password", salt, payload)
			if !bytes.Equal(wire, expected) {
				t.Fatal("stream wire differs from the SIP004 reference")
			}

			decoder, err := suite.NewAEADStream(salt)
			if err != nil {
				t.Fatal(err)
			}
			var decoded []byte
			for _, octet := range wire {
				decoded, err = decoder.Open(decoded, []byte{octet})
				if err != nil {
					t.Fatal(err)
				}
			}
			if !bytes.Equal(decoded, payload) {
				t.Fatalf("decoded %d bytes, want %d", len(decoded), len(payload))
			}
			if decoder.Pending() || !decoder.Authenticated() {
				t.Fatalf("pending=%v authenticated=%v", decoder.Pending(), decoder.Authenticated())
			}
		})
	}
}

func TestSIP004RejectsTamperingAndOversizedRecord(t *testing.T) {
	for _, method := range sip004Methods {
		t.Run(method, func(t *testing.T) {
			suite, err := NewSuite(method, "server-password")
			if err != nil {
				t.Fatal(err)
			}
			salt := testSalt(suite.IVLen())
			encoder, _ := suite.NewAEADStream(salt)
			wire, err := encoder.Seal(nil, []byte("authenticated payload"))
			if err != nil {
				t.Fatal(err)
			}
			for _, offset := range []int{0, aeadLengthBoxSize, len(wire) - 1} {
				tampered := bytes.Clone(wire)
				tampered[offset] ^= 0x80
				decoder, _ := suite.NewAEADStream(salt)
				if _, err = decoder.Open(nil, tampered); !errors.Is(err, ErrAuthentication) {
					t.Fatalf("tamper at %d: %v", offset, err)
				}
			}

			aead := referenceAEAD(t, method, "server-password", salt)
			var size [2]byte
			binary.BigEndian.PutUint16(size[:], maxAEADPayload+1)
			oversized := aead.Seal(nil, make([]byte, aead.NonceSize()), size[:], nil)
			decoder, _ := suite.NewAEADStream(salt)
			if _, err = decoder.Open(nil, oversized); !errors.Is(err, ErrRecordTooLarge) {
				t.Fatalf("oversized record: %v", err)
			}
		})
	}
}

func TestSIP004PacketRejectsTampering(t *testing.T) {
	for _, method := range sip004Methods {
		suite, err := NewSuite(method, "server-password")
		if err != nil {
			t.Fatal(err)
		}
		packet, err := suite.SealPacket(nil, []byte("payload"), testSalt(suite.IVLen()))
		if err != nil {
			t.Fatal(err)
		}
		packet[len(packet)-1] ^= 1
		if _, _, err = suite.OpenPacket(packet); !errors.Is(err, ErrAuthentication) {
			t.Fatalf("%s: %v", method, err)
		}
	}
}

func TestSIP004AliasAndModeSeparation(t *testing.T) {
	suite, err := NewSuite("chacha20-poly1305", "password")
	if err != nil {
		t.Fatal(err)
	}
	if suite.Name() != "chacha20-ietf-poly1305" || !suite.IsAEAD() {
		t.Fatalf("name=%q AEAD=%v", suite.Name(), suite.IsAEAD())
	}
	if _, err = suite.NewEncryptStream(make([]byte, suite.IVLen())); !errors.Is(err, ErrCipherMode) {
		t.Fatalf("stream mode: %v", err)
	}
	classic, err := NewSuite("aes-128-cfb", "password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = classic.NewAEADStream(make([]byte, classic.IVLen())); !errors.Is(err, ErrCipherMode) {
		t.Fatalf("AEAD mode: %v", err)
	}
}

func referenceSealStream(t *testing.T, method, password string, salt, plaintext []byte) []byte {
	t.Helper()
	aead := referenceAEAD(t, method, password, salt)
	nonce := make([]byte, aead.NonceSize())
	var wire []byte
	for len(plaintext) > 0 {
		chunkSize := min(len(plaintext), maxAEADPayload)
		var size [2]byte
		binary.BigEndian.PutUint16(size[:], uint16(chunkSize))
		wire = aead.Seal(wire, nonce, size[:], nil)
		referenceIncrementNonce(nonce)
		wire = aead.Seal(wire, nonce, plaintext[:chunkSize], nil)
		referenceIncrementNonce(nonce)
		plaintext = plaintext[chunkSize:]
	}
	return wire
}

func referenceAEAD(t *testing.T, method, password string, salt []byte) stdcipher.AEAD {
	t.Helper()
	keyLen := len(salt)
	masterKey := deriveKey(password, keyLen)
	subkey, err := hkdf.Key(sha1.New, masterKey, salt, "ss-subkey", keyLen)
	if err != nil {
		t.Fatal(err)
	}
	var aead stdcipher.AEAD
	switch method {
	case "aes-128-gcm", "aes-192-gcm", "aes-256-gcm":
		block, blockErr := aes.NewCipher(subkey)
		if blockErr != nil {
			t.Fatal(blockErr)
		}
		aead, err = stdcipher.NewGCM(block)
	case "chacha20-ietf-poly1305":
		aead, err = chacha20poly1305.New(subkey)
	case "xchacha20-ietf-poly1305":
		aead, err = chacha20poly1305.NewX(subkey)
	default:
		t.Fatalf("unknown reference method %q", method)
	}
	if err != nil {
		t.Fatal(err)
	}
	return aead
}

func referenceIncrementNonce(nonce []byte) {
	for index := 0; index < len(nonce); index++ {
		nonce[index]++
		if nonce[index] != 0 {
			break
		}
	}
}

func testSalt(length int) []byte {
	salt := make([]byte, length)
	for index := range salt {
		salt[index] = byte(index*17 + 11)
	}
	return salt
}
