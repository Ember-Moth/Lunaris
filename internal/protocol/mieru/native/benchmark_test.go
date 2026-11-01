// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package native

import (
	"net"
	"testing"
	"time"
)

func BenchmarkPacketSeal1200(b *testing.B) {
	prepared, err := PrepareUsers([]User{{Name: "benchmark-user", Password: "benchmark-password"}})
	if err != nil {
		b.Fatal(err)
	}
	user := prepared.snapshot.users[0]
	keys, err := user.keysAt(time.Now())
	if err != nil {
		b.Fatal(err)
	}
	payload := make([]byte, 1200)
	meta := metadata{protocol: dataServerToClient, sessionID: 1, seq: 1, windowSize: 4096, payloadLen: uint16(len(payload))}
	b.ReportAllocs()
	for b.Loop() {
		result, sealErr := sealPacket(nil, meta, payload, keys.aead[1], user.name)
		if sealErr != nil || len(result) != len(payload)+packetOverhead {
			b.Fatal(sealErr)
		}
	}
}

func BenchmarkPacketSealPattern1200(b *testing.B) {
	prepared, err := PrepareUsers([]User{{Name: "benchmark-user", Password: "benchmark-password"}})
	if err != nil {
		b.Fatal(err)
	}
	user := prepared.snapshot.users[0]
	keys, err := user.keysAt(time.Now())
	if err != nil {
		b.Fatal(err)
	}
	pattern, err := decodeTrafficPattern("")
	if err != nil {
		b.Fatal(err)
	}
	payload := make([]byte, 1200)
	meta := metadata{protocol: dataServerToClient, sessionID: 1, seq: 1, windowSize: 4096, payloadLen: uint16(len(payload))}
	b.ReportAllocs()
	for b.Loop() {
		result, sealErr := sealPacketPattern(nil, meta, payload, keys.aead[1], user.name, pattern, true, defaultMTU)
		if sealErr != nil || len(result) < len(payload)+packetOverhead || len(result) > defaultMTU {
			b.Fatal(sealErr)
		}
	}
}

func BenchmarkServerWritePacketPattern1200(b *testing.B) {
	prepared, err := PrepareUsers([]User{{Name: "benchmark-user", Password: "benchmark-password"}})
	if err != nil {
		b.Fatal(err)
	}
	user := prepared.snapshot.users[0]
	keys, _ := user.keysAt(time.Now())
	pattern, err := decodeTrafficPattern("")
	if err != nil {
		b.Fatal(err)
	}
	pattern.nonce.applyAll = true
	server := &Server{packet: discardPacketConn{}, pattern: pattern}
	server.packetBuffers.New = func() any {
		buffer := make([]byte, 0, defaultMTU)
		return &buffer
	}
	remote := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 12345}
	payload := make([]byte, 1200)
	meta := metadata{protocol: dataServerToClient, sessionID: 1, seq: 1, windowSize: 4096, payloadLen: uint16(len(payload))}
	b.ReportAllocs()
	for b.Loop() {
		if writeErr := server.writePacket(meta, payload, keys.aead[1], user.name, remote, nil); writeErr != nil {
			b.Fatal(writeErr)
		}
	}
}

type discardPacketConn struct{}

func (discardPacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (discardPacketConn) WriteTo(payload []byte, _ net.Addr) (int, error) {
	return len(payload), nil
}
func (discardPacketConn) Close() error                     { return nil }
func (discardPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (discardPacketConn) SetDeadline(time.Time) error      { return nil }
func (discardPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (discardPacketConn) SetWriteDeadline(time.Time) error { return nil }

func BenchmarkPacketOpen1200(b *testing.B) {
	prepared, err := PrepareUsers([]User{{Name: "benchmark-user", Password: "benchmark-password"}})
	if err != nil {
		b.Fatal(err)
	}
	user := prepared.snapshot.users[0]
	keys, _ := user.keysAt(time.Now())
	payload := make([]byte, 1200)
	meta := metadata{protocol: dataClientToServer, sessionID: 1, seq: 1, windowSize: 4096, payloadLen: uint16(len(payload))}
	packet, err := sealPacket(nil, meta, payload, keys.aead[1], user.name)
	if err != nil {
		b.Fatal(err)
	}
	dst := make([]byte, 0, len(payload))
	ciphertext := packet[packetHeaderSize:]
	nonce := packet[:nonceSize]
	b.ReportAllocs()
	for b.Loop() {
		plain, openErr := keys.aead[1].Open(dst, nonce, ciphertext, nil)
		if openErr != nil || len(plain) != len(payload) {
			b.Fatal(openErr)
		}
	}
}

func BenchmarkDiscoverCachedUser(b *testing.B) {
	users := make([]User, 1024)
	for index := range users {
		users[index] = User{Name: "user-" + benchmarkDecimal(index), Password: "password-" + benchmarkDecimal(index)}
	}
	prepared, err := PrepareUsers(users)
	if err != nil {
		b.Fatal(err)
	}
	target := prepared.snapshot.users[len(prepared.snapshot.users)-1]
	keys, _ := target.keysAt(time.Now())
	meta := metadata{protocol: openSessionRequest, sessionID: 1}
	packet, err := sealPacket(nil, meta, nil, keys.aead[1], target.name)
	if err != nil {
		b.Fatal(err)
	}
	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 12345}
	if _, err = prepared.snapshot.discover(packet[:packetHeaderSize], make([]byte, 0, metadataLength), remote); err != nil {
		b.Fatal(err)
	}
	var scratch [metadataLength]byte
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, discoverErr := prepared.snapshot.discover(packet[:packetHeaderSize], scratch[:0], remote); discoverErr != nil {
			b.Fatal(discoverErr)
		}
	}
}

func BenchmarkDiscoverRegistryHint1K(b *testing.B) {
	users := make([]User, 1024)
	for index := range users {
		users[index] = User{Name: "user-" + benchmarkDecimal(index), Password: "password-" + benchmarkDecimal(index)}
	}
	prepared, err := PrepareUsers(users)
	if err != nil {
		b.Fatal(err)
	}
	target := prepared.snapshot.users[len(prepared.snapshot.users)-1]
	keys, _ := target.keysAt(time.Now())
	packet, err := sealPacket(nil, metadata{protocol: openSessionRequest, sessionID: 1}, nil, keys.aead[1], target.name)
	if err != nil {
		b.Fatal(err)
	}
	var scratch [metadataLength]byte
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, discoverErr := prepared.snapshot.discover(packet[:packetHeaderSize], scratch[:0], nil); discoverErr != nil {
			b.Fatal(discoverErr)
		}
	}
}

func BenchmarkDiscoverCachedUserParallel(b *testing.B) {
	prepared, err := PrepareUsers([]User{{Name: "benchmark-user", Password: "benchmark-password"}})
	if err != nil {
		b.Fatal(err)
	}
	target := prepared.snapshot.users[0]
	keys, _ := target.keysAt(time.Now())
	packet, err := sealPacket(nil, metadata{protocol: openSessionRequest, sessionID: 1}, nil, keys.aead[1], target.name)
	if err != nil {
		b.Fatal(err)
	}
	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 12345}
	var initial [metadataLength]byte
	if _, err = prepared.snapshot.discover(packet[:packetHeaderSize], initial[:0], remote); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.RunParallel(func(parallel *testing.PB) {
		var scratch [metadataLength]byte
		for parallel.Next() {
			if _, discoverErr := prepared.snapshot.discover(packet[:packetHeaderSize], scratch[:0], remote); discoverErr != nil {
				b.Error(discoverErr)
				return
			}
		}
	})
}

func benchmarkDecimal(value int) string {
	if value == 0 {
		return "0"
	}
	var storage [20]byte
	position := len(storage)
	for value != 0 {
		position--
		storage[position] = byte('0' + value%10)
		value /= 10
	}
	return string(storage[position:])
}

func BenchmarkPrepareUsers10K(b *testing.B) {
	users := make([]User, 10000)
	for index := range users {
		users[index] = User{Name: "user-" + benchmarkDecimal(index), Password: "password-" + benchmarkDecimal(index)}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := PrepareUsers(users); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPreparedInstall10K(b *testing.B) {
	users := make([]User, 10000)
	for index := range users {
		users[index] = User{Name: "user-" + benchmarkDecimal(index), Password: "password-" + benchmarkDecimal(index)}
	}
	prepared, err := PrepareUsers(users)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		snapshot := *prepared.snapshot
		snapshot.cache = newSourceCache()
		benchmarkSnapshot = &snapshot
	}
}

var benchmarkSnapshot *userSnapshot
