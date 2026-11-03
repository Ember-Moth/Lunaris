// SPDX-License-Identifier: GPL-3.0-or-later
// Adapted from Polaris; see THIRD_PARTY_NOTICES.md.
package kcptun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/ingress"
	"github.com/metacubex/kcp-go"
	"github.com/sagernet/smux"
)

func TestNewServerRequiresExplicitSecureConfiguration(t *testing.T) {
	if _, err := NewServer(Config{}); !errors.Is(err, errEmptyKey) {
		t.Fatalf("empty key error = %v", err)
	}
	if _, err := NewServer(Config{Key: "secret", Crypt: "none"}); !errors.Is(err, errInsecureCrypt) {
		t.Fatalf("insecure crypt error = %v", err)
	}
	server, err := NewServer(Config{Key: "secret", Crypt: "none", AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	if cap(server.sessions) != defaultMaxSessions || cap(server.streams) != defaultMaxActiveStreams ||
		server.config.MaxStreams != defaultMaxStreams {
		t.Fatalf("default limits = sessions %d, streams %d/%d", cap(server.sessions), server.config.MaxStreams, cap(server.streams))
	}
}

func TestNewServerSupportsModernAESGCM(t *testing.T) {
	for _, crypt := range []string{"aes-128-gcm", "aes-192-gcm", "aes-256-gcm"} {
		t.Run(crypt, func(t *testing.T) {
			if _, err := NewServer(Config{Key: "secret", Crypt: crypt}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestServerStopsWhenContextIsCanceled(t *testing.T) {
	server, err := NewServer(Config{
		Key: "secret", Crypt: "aes", MTU: 1350, SndWnd: 128, RcvWnd: 512,
		DataShard: 10, ParityShard: 3, SockBuf: 1 << 20, SmuxVer: 1,
		SmuxBuf: 1 << 20, FrameSize: 8192, StreamBuf: 1 << 20, KeepAlive: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = packetConn.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- server.Serve(ctx, packetConn, func(net.Conn) {}) }()
	cancel()

	select {
	case <-result:
	case <-time.After(time.Second):
		t.Fatal("Serve() did not stop after cancellation")
	}
}

func TestUnauthenticatedKCPSessionReleasesBudget(t *testing.T) {
	cfg := Config{Key: "secret", Crypt: "aes", MTU: 1350, SndWnd: 128, RcvWnd: 128, DataShard: 10, ParityShard: 3, SockBuf: 1 << 20, SmuxVer: 1, SmuxBuf: 1 << 20, StreamBuf: 1 << 20, FrameSize: 8192, KeepAlive: 10, NoComp: true, HandshakeTimeout: 120 * time.Millisecond, MaxPendingSessions: 1}
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(ctx, socket, func(net.Conn) { t.Error("unauthenticated test opened a stream") })
	}()
	block, err := newBlock(cfg)
	if err != nil {
		t.Fatal(err)
	}
	client, err := kcp.DialWithOptions(socket.LocalAddr().String(), block, cfg.DataShard, cfg.ParityShard)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	configureKCP(client, cfg)
	// A valid smux keep-alive has no logical stream and must not authenticate KCP.
	if _, err := client.Write([]byte{1, 3, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for len(server.pending) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(server.pending) != 1 {
		t.Fatal("KCP session was not admitted")
	}
	for (len(server.pending) != 0 || len(server.sessions) != 0) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(server.pending) != 0 || len(server.sessions) != 0 {
		t.Fatal("unauthenticated session retained admission budget")
	}
	cancel()
	socket.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("KCP server did not stop")
	}
}

func TestWildcardKCPSessionsKeepLocalEndpoints(t *testing.T) {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	var local netip.Addr
	for _, a := range addresses {
		p, e := netip.ParsePrefix(a.String())
		if e == nil && p.Addr().Is4() && !p.Addr().IsLoopback() && !p.Addr().IsLinkLocalUnicast() {
			local = p.Addr()
			break
		}
	}
	if !local.IsValid() {
		t.Skip("no local non-loopback IPv4 address")
	}
	cfg := Config{Key: "secret", Crypt: "aes", MTU: 1350, SndWnd: 128, RcvWnd: 128, DataShard: 10, ParityShard: 3, SockBuf: 1 << 20, SmuxVer: 1, SmuxBuf: 1 << 20, StreamBuf: 1 << 20, FrameSize: 8192, KeepAlive: 10, NoComp: true, HandshakeTimeout: time.Second, MaxSessions: 4, MaxPendingSessions: 4}
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	socket, err := ingress.PacketConn(raw)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- ingress.ServeByLocal(ctx, socket, func(ctx context.Context, c net.PacketConn) error {
			return server.Serve(ctx, c, func(stream net.Conn) {
				defer stream.Close()
				var request [1]byte
				if _, err := io.ReadFull(stream, request[:]); err != nil {
					return
				}
				stream.(interface{ ProtocolReady() }).ProtocolReady()
				_, _ = io.WriteString(stream, ingress.AddressIP(stream.LocalAddr()).String()+"\n")
			})
		})
	}()
	port := raw.LocalAddr().(*net.UDPAddr).Port
	for _, ip := range []netip.Addr{local, netip.MustParseAddr("127.0.0.1")} {
		block, err := newBlock(cfg)
		if err != nil {
			t.Fatal(err)
		}
		carrier, err := kcp.DialWithOptions(net.JoinHostPort(ip.String(), fmt.Sprint(port)), block, cfg.DataShard, cfg.ParityShard)
		if err != nil {
			t.Fatal(err)
		}
		configureKCP(carrier, cfg)
		mux, err := smux.Client(carrier, smuxConfig(cfg))
		if err != nil {
			carrier.Close()
			t.Fatal(err)
		}
		stream, err := mux.OpenStream()
		if err != nil {
			mux.Close()
			carrier.Close()
			t.Fatal(err)
		}
		stream.SetDeadline(time.Now().Add(2 * time.Second))
		stream.Write([]byte{1})
		reply, err := io.ReadAll(stream)
		stream.Close()
		mux.Close()
		carrier.Close()
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(string(reply)) != ip.String() {
			t.Fatal("KCP local endpoint lost", string(reply), ip)
		}
	}
	cancel()
	raw.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("KCP local sockets survived shutdown")
	}
	if len(server.sessions) != 0 || len(server.pending) != 0 || len(server.streams) != 0 {
		t.Fatal("KCP shared resource budgets leaked")
	}
}
