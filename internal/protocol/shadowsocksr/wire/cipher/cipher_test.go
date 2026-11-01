// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package cipher

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

func TestPacketRoundTrip(t *testing.T) {
	methods := []string{
		"none",
		"aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
		"aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
		"rc4-md5", "chacha20", "chacha20-ietf",
		"aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
		"chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
	}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			suite, err := NewSuite(method, "server-password")
			if err != nil {
				t.Fatal(err)
			}
			iv := make([]byte, suite.IVLen())
			for index := range iv {
				iv[index] = byte(index*7 + 3)
			}
			plaintext := bytes.Repeat([]byte{0x5a}, 513)
			packet, err := suite.SealPacket(make([]byte, 0, len(iv)+len(plaintext)), plaintext, iv)
			if err != nil {
				t.Fatal(err)
			}
			decoded, actualIV, err := suite.OpenPacket(packet)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(decoded, plaintext) || !bytes.Equal(actualIV, iv) {
				t.Fatal("packet round trip differs")
			}
		})
	}
}

func TestLegacyWireVectors(t *testing.T) {
	vectors := map[string]string{
		"none":          "252a3370c1b76874608df4bddcec49b44df2367ea4b618aa7a5acb4b35709c97",
		"aes-128-ctr":   "8d7d6da50c35a1c6d38430a8387ba79b21485fdbb411acb8e7968cc7063479b7",
		"aes-192-ctr":   "8bf549f7243f10f884b9fb4ef48b6d008e3418bc7574286954441bd7ae61e75a",
		"aes-256-ctr":   "51b8ea99a8df790b1d3aa878d6be9a1a575fbe85b73d0e67241763eff6a1d831",
		"aes-128-cfb":   "d4aedbdd6f0ac6799f13c7266e36559462ad77a0c41efd41bf64822f724db3c1",
		"aes-192-cfb":   "b66f97da4d3acc904f7996e7a8cc94b9e1ba2b57cbf13954e99508cadc186e3e",
		"aes-256-cfb":   "a1052efbb4f24f2419f9f3c06819c009f10481fba13bd5e7fefa05698e7b6dea",
		"rc4-md5":       "1572ab5ccdd79129b7cfbda280ca496da533f82ef50f2e13271b9230a7dfdee0",
		"chacha20":      "dfa195c97ba926ff331b9f1d00cb164d963e90fded1469742843804281179ec7",
		"chacha20-ietf": "db639d28698d0fba030151d001e342ff1d70f2ac032b3fda05248367c2bd3aac",
	}
	for method, expectedHex := range vectors {
		t.Run(method, func(t *testing.T) {
			suite, err := NewSuite(method, "server-password")
			if err != nil {
				t.Fatal(err)
			}
			iv := make([]byte, suite.IVLen())
			for index := range iv {
				iv[index] = byte(index*7 + 3)
			}
			payload := bytes.Repeat([]byte{0x5a}, 4097)
			wire, err := suite.SealPacket(make([]byte, 0, len(iv)+len(payload)), payload, iv)
			if err != nil {
				t.Fatal(err)
			}
			expected, _ := hex.DecodeString(expectedHex)
			actual := sha256.Sum256(wire)
			if !bytes.Equal(actual[:], expected) {
				t.Fatalf("sha256=%x, want %x", actual, expected)
			}
		})
	}
}

func TestUnsupportedMethod(t *testing.T) {
	for _, method := range []string{"unknown", "2022-blake3-aes-128-gcm"} {
		_, err := NewSuite(method, "password")
		if !errors.Is(err, ErrUnsupportedMethod) {
			t.Fatalf("%s: got %v", method, err)
		}
	}
}

func BenchmarkSealPacket512(b *testing.B) {
	suite, err := NewSuite("aes-128-cfb", "server-password")
	if err != nil {
		b.Fatal(err)
	}
	iv := make([]byte, suite.IVLen())
	plaintext := make([]byte, 512)
	destination := make([]byte, 0, len(iv)+len(plaintext))
	b.ReportAllocs()
	for b.Loop() {
		if _, err = suite.SealPacket(destination[:0], plaintext, iv); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSealPacket512AEAD(b *testing.B) {
	suite, err := NewSuite("aes-128-gcm", "server-password")
	if err != nil {
		b.Fatal(err)
	}
	salt := make([]byte, suite.IVLen())
	plaintext := make([]byte, 512)
	destination := make([]byte, 0, suite.PacketOverhead()+len(plaintext))
	b.ReportAllocs()
	b.SetBytes(int64(len(plaintext)))
	for b.Loop() {
		if _, err = suite.SealPacket(destination[:0], plaintext, salt); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSIP004StreamSeal8K(b *testing.B) {
	for _, method := range []string{"aes-128-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305"} {
		b.Run(method, func(b *testing.B) {
			suite, err := NewSuite(method, "server-password")
			if err != nil {
				b.Fatal(err)
			}
			stream, err := suite.NewAEADStream(make([]byte, suite.IVLen()))
			if err != nil {
				b.Fatal(err)
			}
			plaintext := make([]byte, 8*1024)
			destination := make([]byte, 0, len(plaintext)+aeadLengthBoxSize+aeadTagSize)
			b.ReportAllocs()
			b.SetBytes(int64(len(plaintext)))
			for b.Loop() {
				if _, err = stream.Seal(destination[:0], plaintext); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
