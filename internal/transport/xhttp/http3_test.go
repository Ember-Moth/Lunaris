// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package xhttp

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go/http3"
)

func TestH3ClientClosesPacketConn(t *testing.T) {
	serverTLS, clientTLS := testH3TLSConfigs(t)
	config := testTransportConfig(t, ModePacketUp)
	_, address := startH3TestServer(t, config, serverTLS, "127.0.0.1:0")

	t.Run("failed dial", func(t *testing.T) {
		untrusted := clientTLS.Clone()
		untrusted.InsecureSkipVerify = false
		dialer := new(recordingPacketDialer)
		client := NewClient(ClientOptions{
			Context: context.Background(), Config: config, Server: address.String(), TLSConfig: untrusted,
			DialPacket: dialer.dial,
		})
		defer func() { _ = client.Close() }()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := client.DialContext(ctx)
		if err == nil {
			_ = conn.Close()
			t.Fatal("dial with an untrusted certificate succeeded")
		}
		dialer.assertClosed(t, address)
	})

	t.Run("client close", func(t *testing.T) {
		dialer := new(recordingPacketDialer)
		client := NewClient(ClientOptions{
			Context: context.Background(), Config: config, Server: address.String(), TLSConfig: clientTLS,
			DialPacket: dialer.dial,
		})
		assertTransportRoundTrip(t, client)
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
		dialer.assertClosed(t, address)
	})
}

func TestH3ClientClosesPacketConnOfLostConnection(t *testing.T) {
	serverTLS, clientTLS := testH3TLSConfigs(t)
	config := testTransportConfig(t, ModePacketUp)
	server, address := startH3TestServer(t, config, serverTLS, "127.0.0.1:0")
	dialer := new(recordingPacketDialer)
	client := NewClient(ClientOptions{
		Context: context.Background(), Config: config, Server: address.String(), TLSConfig: clientTLS,
		DialPacket: dialer.dial,
	})
	defer func() { _ = client.Close() }()
	assertTransportRoundTrip(t, client)

	// Closing the server closes its QUIC connection to the client, which stays
	// open and redials on its next request.
	_ = server.Close()
	lost := dialer.opened()
	if len(lost) != 1 {
		t.Fatalf("HTTP/3 client opened %d packet conns, want 1", len(lost))
	}
	waitPacketConnClosed(t, lost[0], address)

	startH3TestServer(t, config, serverTLS, address.String())
	assertTransportRoundTrip(t, client)
	if opened := dialer.opened(); len(opened) != 2 {
		t.Fatalf("HTTP/3 client opened %d packet conns after redial, want 2", len(opened))
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	dialer.assertClosed(t, address)
}

func testH3TLSConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	serverTLS, clientTLS := testTLSConfigs(t)
	serverTLS.NextProtos = []string{http3.NextProtoH3}
	clientTLS.NextProtos = []string{http3.NextProtoH3}
	return serverTLS, clientTLS
}

func startH3TestServer(t *testing.T, config Config, serverTLS *tls.Config, address string) (*Server, net.Addr) {
	t.Helper()
	packet, err := (&net.ListenConfig{}).ListenPacket(context.Background(), "udp", address)
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(context.Background(), config, serverTLS, echoHandler{})
	go func() { _ = server.ServePacket(packet) }()
	t.Cleanup(func() { _ = server.Close() })
	return server, packet.LocalAddr()
}

// recordingPacketDialer opens the default HTTP/3 client sockets and keeps them
// so a test can check that the client closed them.
type recordingPacketDialer struct {
	mu      sync.Mutex
	packets []net.PacketConn
}

func (dialer *recordingPacketDialer) dial(ctx context.Context, address string) (net.PacketConn, net.Addr, error) {
	packet, remote, err := defaultPacketDialer(ctx, address)
	if err == nil {
		dialer.mu.Lock()
		dialer.packets = append(dialer.packets, packet)
		dialer.mu.Unlock()
	}
	return packet, remote, err
}

func (dialer *recordingPacketDialer) opened() []net.PacketConn {
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	return append([]net.PacketConn(nil), dialer.packets...)
}

func (dialer *recordingPacketDialer) assertClosed(t *testing.T, address net.Addr) {
	t.Helper()
	packets := dialer.opened()
	if len(packets) == 0 {
		t.Fatal("HTTP/3 client opened no packet conn")
	}
	for _, packet := range packets {
		// quic.Transport.Close leaves a caller-supplied socket open.
		if err := writePacket(packet, address); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("write after close error = %v, want net.ErrClosed", err)
		}
	}
}

// waitPacketConnClosed polls until the socket is closed. The client releases
// the transport of a lost connection after the connection's context ends.
func waitPacketConnClosed(t *testing.T, packet net.PacketConn, address net.Addr) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := writePacket(packet, address)
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("write to the lost connection's socket error = %v, want net.ErrClosed", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func writePacket(packet net.PacketConn, address net.Addr) error {
	_, err := packet.WriteTo([]byte{0}, address)
	return err
}
