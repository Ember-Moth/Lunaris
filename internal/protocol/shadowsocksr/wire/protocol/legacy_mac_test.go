// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package protocol

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"hash"
	"strconv"
	"sync"
	"testing"
)

func TestLegacyMACMatchesStandardLibrary(t *testing.T) {
	factories := []struct {
		name string
		new  func() hash.Hash
	}{
		{name: "md5", new: md5.New},
		{name: "sha1", new: sha1.New},
	}
	for _, factory := range factories {
		for _, keyLength := range []int{0, 1, 16, 20, 60, 64, 65, 100} {
			t.Run(factory.name+"/key="+strconv.Itoa(keyLength), func(t *testing.T) {
				key := bytes.Repeat([]byte{byte(keyLength + 1)}, keyLength)
				data := bytes.Repeat([]byte{0xa5}, 8193)
				standard := hmac.New(factory.new, key)
				_, _ = standard.Write(data)
				want := standard.Sum(nil)
				worker := newLegacyMAC(factory.new)
				if got := worker.sum(key, data); !bytes.Equal(got, want) {
					t.Fatalf("HMAC mismatch: got %x, want %x", got, want)
				}

				split := keyLength / 2
				if got := worker.sumJoined(key[:split], key[split:], data); !bytes.Equal(got, want) {
					t.Fatalf("joined HMAC mismatch: got %x, want %x", got, want)
				}

				const sequence = uint32(0x12345678)
				var sequenceBytes [4]byte
				binary.LittleEndian.PutUint32(sequenceBytes[:], sequence)
				standard = hmac.New(factory.new, append(append([]byte(nil), key...), sequenceBytes[:]...))
				_, _ = standard.Write(data)
				want = standard.Sum(nil)
				if got := worker.sumSequence(key, sequence, data); !bytes.Equal(got, want) {
					t.Fatalf("sequence HMAC mismatch: got %x, want %x", got, want)
				}
			})
		}
	}
}

func TestAuthPacketWorkersAreConcurrentSafe(t *testing.T) {
	userID := [4]byte{1, 2, 3, 4}
	credential := Credential{Key: []byte("known-user-key!"), HeaderKey: make([]byte, 16)}
	for _, name := range []string{"auth_aes128_sha1", "auth_chain_a", "auth_chain_f"} {
		t.Run(name, func(t *testing.T) {
			definition, err := New(Config{
				Name: name, ServerKey: []byte("server-key-16byt"), Users: map[[4]byte]Credential{userID: credential},
			})
			if err != nil {
				t.Fatal(err)
			}
			var workers sync.WaitGroup
			for range 64 {
				workers.Go(func() {
					for range 100 {
						if _, encodeErr := definition.EncodePacket(nil, []byte("concurrent packet"), userID, nil); encodeErr != nil {
							t.Errorf("EncodePacket: %v", encodeErr)
							return
						}
					}
				})
			}
			workers.Wait()
		})
	}
}

func TestUnknownUserStillPerformsProtocolAuthentication(t *testing.T) {
	knownID := [4]byte{1, 2, 3, 4}
	unknownID := [4]byte{9, 8, 7, 6}
	credential := Credential{Key: []byte("known-user-key!"), HeaderKey: make([]byte, 16)}

	aesDefinition := newAuthAESDefinition(Config{
		Name: "auth_aes128_md5", ServerKey: []byte("server-key"), Users: map[[4]byte]Credential{knownID: credential},
	})
	aesPacket := make([]byte, 8)
	copy(aesPacket[:4], unknownID[:])
	if _, _, err := aesDefinition.DecodePacket(nil, aesPacket, nil); err != ErrUnknownUser {
		t.Fatalf("auth_aes unknown user: got %v", err)
	}
	copy(aesPacket[:4], knownID[:])
	if _, _, err := aesDefinition.DecodePacket(nil, aesPacket, nil); err != ErrAuthentication {
		t.Fatalf("auth_aes known user with invalid MAC: got %v", err)
	}

	chainDefinition := newAuthChainDefinition(Config{
		Name: "auth_chain_a", ServerKey: []byte("server-key"), Users: map[[4]byte]Credential{knownID: credential},
	})
	chainPacket := make([]byte, 9)
	authData := chainPacket[1:4]
	headerMAC := hmac.New(md5.New, chainDefinition.serverKey)
	_, _ = headerMAC.Write(authData)
	headerHash := headerMAC.Sum(nil)
	binary.LittleEndian.PutUint32(chainPacket[4:8],
		binary.LittleEndian.Uint32(unknownID[:])^binary.LittleEndian.Uint32(headerHash[:4]))
	if _, _, err := chainDefinition.DecodePacket(nil, chainPacket, nil); err != ErrUnknownUser {
		t.Fatalf("auth_chain unknown user: got %v", err)
	}
	binary.LittleEndian.PutUint32(chainPacket[4:8],
		binary.LittleEndian.Uint32(knownID[:])^binary.LittleEndian.Uint32(headerHash[:4]))
	if _, _, err := chainDefinition.DecodePacket(nil, chainPacket, nil); err != ErrAuthentication {
		t.Fatalf("auth_chain known user with invalid MAC: got %v", err)
	}
}
