// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package shadowsocksr

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
)

func BenchmarkWrapConn(b *testing.B) {
	userID := [4]byte{1, 0, 0, 0}
	connection := benchmarkConn{}
	for _, protocolName := range []string{
		"auth_aes128_sha1", "auth_chain_a", "auth_chain_b", "auth_chain_c", "auth_chain_d", "auth_chain_e", "auth_chain_f",
	} {
		b.Run(protocolName, func(b *testing.B) {
			server, err := NewServer(benchmarkConfig(protocolName), map[[4]byte]string{userID: "user-password"})
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				wrapped, wrapErr := server.WrapConn(connection)
				if wrapErr != nil {
					b.Fatal(wrapErr)
				}
				if closeErr := wrapped.Close(); closeErr != nil {
					b.Fatal(closeErr)
				}
			}
		})
	}
}

func BenchmarkWrapConnSIP004(b *testing.B) {
	connection := benchmarkConn{}
	for _, method := range []string{"aes-128-gcm", "chacha20-ietf-poly1305"} {
		b.Run(method, func(b *testing.B) {
			server, err := NewServer(ServerConfig{Method: method, Password: "server-password", Protocol: "origin",
				Obfs: "plain", Host: "127.0.0.1", Port: 8388}, map[[4]byte]string{{1}: "user-password"})
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				wrapped, wrapErr := server.WrapConn(connection)
				if wrapErr != nil {
					b.Fatal(wrapErr)
				}
				if closeErr := wrapped.Close(); closeErr != nil {
					b.Fatal(closeErr)
				}
			}
		})
	}
}

func BenchmarkPacketEncode512(b *testing.B) {
	userID := [4]byte{1, 0, 0, 0}
	payload := bytes.Repeat([]byte{0x5a}, 512)
	for _, protocolName := range []string{
		"auth_aes128_sha1", "auth_chain_a", "auth_chain_b", "auth_chain_c", "auth_chain_d", "auth_chain_e", "auth_chain_f",
	} {
		b.Run(protocolName, func(b *testing.B) {
			server, err := NewServer(benchmarkConfig(protocolName), map[[4]byte]string{userID: "user-password"})
			if err != nil {
				b.Fatal(err)
			}
			codec, err := server.NewPacketCodec()
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				packet := buf.NewSize(len(payload) + 8*1024 + 64)
				_, _ = packet.Write(payload)
				encoded, encodeErr := codec.Encode(packet, userID)
				if encodeErr != nil {
					packet.Release()
					b.Fatal(encodeErr)
				}
				encoded.Release()
			}
		})
	}
}

func benchmarkConfig(protocolName string) ServerConfig {
	return ServerConfig{Method: "aes-128-cfb", Password: "server-password", Protocol: protocolName,
		ProtocolParam: "1:user-password", Obfs: "plain", Host: "127.0.0.1", Port: 8388}
}

type benchmarkConn struct{}

func (benchmarkConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (benchmarkConn) Write(value []byte) (int, error)  { return len(value), nil }
func (benchmarkConn) Close() error                     { return nil }
func (benchmarkConn) LocalAddr() net.Addr              { return benchmarkAddr("127.0.0.1:8388") }
func (benchmarkConn) RemoteAddr() net.Addr             { return benchmarkAddr("127.0.0.1:10000") }
func (benchmarkConn) SetDeadline(time.Time) error      { return nil }
func (benchmarkConn) SetReadDeadline(time.Time) error  { return nil }
func (benchmarkConn) SetWriteDeadline(time.Time) error { return nil }

type benchmarkAddr string

func (benchmarkAddr) Network() string        { return "tcp" }
func (address benchmarkAddr) String() string { return string(address) }
