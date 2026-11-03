// SPDX-License-Identifier: GPL-3.0-only
package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/ingress"
	"github.com/Ember-Moth/Lunaris/internal/model"
)

func TestCoalescedLookupOutlivesCanceledLeader(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	address := startUDPServer(t, func(query []byte) []byte {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-release
		return makeResponse(query, []netip.Addr{netip.MustParseAddr("127.0.0.1")})
	})
	resolver := NewResolver(MustCompile(Config{Servers: []model.DNSServer{{Proto: "udp", Address: address}}}), Options{Timeout: time.Second})
	defer resolver.Close()
	first, cancel := context.WithCancel(context.Background())
	defer cancel()
	one, two := make(chan error, 1), make(chan error, 1)
	go func() { _, err := resolver.Exchange(first, "shared.test", dnsTypeA); one <- err }()
	<-entered
	go func() { _, err := resolver.Exchange(context.Background(), "shared.test", dnsTypeA); two <- err }()
	deadline := time.Now().Add(time.Second)
	for resolver.Snapshot().cache.joined(cacheKey{name: "shared.test", qType: dnsTypeA}) == 0 {
		if time.Now().After(deadline) {
			close(release)
			t.Fatal("second lookup did not join")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-one; !errors.Is(err, context.Canceled) {
		close(release)
		t.Fatal(err)
	}
	close(release)
	if err := <-two; err != nil {
		t.Fatal("one caller canceled shared work", err)
	}
	if calls.Load() != 1 {
		t.Fatal("duplicate upstream queries", calls.Load())
	}
}
func TestResolverCloseInterruptsBlockedTCPExchange(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	entered, closed := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(closed)
		c, err := listener.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var size [2]byte
		if _, err := io.ReadFull(c, size[:]); err != nil {
			return
		}
		if _, err := io.CopyN(io.Discard, c, int64(binary.BigEndian.Uint16(size[:]))); err != nil {
			return
		}
		close(entered)
		_, _ = io.Copy(io.Discard, c)
	}()
	resolver := NewResolver(MustCompile(Config{Servers: []model.DNSServer{{Proto: "tcp", Address: listener.Addr().String()}}}), Options{Timeout: 30 * time.Second})
	result := make(chan error, 1)
	go func() { _, err := resolver.Exchange(context.Background(), "close.test", dnsTypeA); result <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		resolver.Close()
		t.Fatal("query did not reach TCP peer")
	}
	done := make(chan struct{})
	go func() { resolver.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("resolver close waited for the old DNS timeout")
	}
	if err := <-result; err == nil {
		t.Fatal("closed exchange succeeded")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("DNS socket survived close")
	}
	if err := resolver.Replace(Config{}); !errors.Is(err, ErrClosed) {
		t.Fatal("closed resolver accepted replacement", err)
	}
}

func TestPacketExchangeKeepsIngressSource(t *testing.T) {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	var source netip.Addr
	for _, a := range addresses {
		p, err := netip.ParsePrefix(a.String())
		if err == nil && p.Addr().Is4() && !p.Addr().IsLoopback() && !p.Addr().IsLinkLocalUnicast() {
			source = p.Addr()
			break
		}
	}
	if !source.IsValid() {
		t.Skip("no local non-loopback IPv4 address")
	}
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	seen := make(chan netip.Addr, 1)
	go func() {
		var b [4096]byte
		n, peer, err := server.ReadFrom(b[:])
		if err != nil {
			return
		}
		seen <- ingress.AddressIP(peer)
		server.WriteTo(makeResponse(b[:n], []netip.Addr{netip.MustParseAddr("127.0.0.1")}), peer)
	}()
	resolver := NewResolver(MustCompile(Config{Servers: []model.DNSServer{{Proto: "udp", Address: server.LocalAddr().String()}}}), Options{Timeout: time.Second})
	defer resolver.Close()
	query, _ := makeQuery("origin.test", dnsTypeA)
	ctx := ingress.WithLocalIP(context.Background(), source)
	if _, err := resolver.ExchangePacket(ctx, query); err != nil {
		t.Fatal(err)
	}
	if got := <-seen; got != source {
		t.Fatal("DNS interception lost ingress source", got, source)
	}
}
