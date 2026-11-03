// SPDX-License-Identifier: GPL-3.0-only
package egress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/ingress"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/net/dns/dnsmessage"
)

func localIPv4(t *testing.T) netip.Addr {
	t.Helper()
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range addresses {
		prefix, e := netip.ParsePrefix(address.String())
		if e != nil {
			continue
		}
		ip := prefix.Addr().Unmap()
		if ip.Is4() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			return ip
		}
	}
	t.Skip("no local non-loopback IPv4 address")
	return netip.Addr{}
}
func TestDirectTCPPreservesSourceAndFallsBack(t *testing.T) {
	local := localIPv4(t)
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	for _, tc := range []struct {
		name         string
		source, want netip.Addr
	}{
		{"assigned", local, local},
		{"unassigned", netip.MustParseAddr("198.18.0.254"), netip.MustParseAddr("127.0.0.1")},
		{"loopback", netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.1")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(ingress.WithLocalIP(context.Background(), tc.source), time.Second)
			defer cancel()
			d := &Direct{}
			outbound, err := d.DialContext(ctx, "tcp", M.SocksaddrFromNet(target.Addr()))
			if err != nil {
				t.Fatal(err)
			}
			defer outbound.Close()
			received, err := target.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer received.Close()
			if got := ingress.AddressIP(received.RemoteAddr()); got != tc.want {
				t.Fatal("unexpected outbound source", got, tc.want)
			}
			if d.Dialer.LocalAddr != nil {
				t.Fatal("shared dialer was mutated")
			}
		})
	}
}
func TestDirectCrossFamilyTCP(t *testing.T) {
	local := localIPv4(t)
	target, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 loopback unavailable")
	}
	defer target.Close()
	ctx, cancel := context.WithTimeout(ingress.WithLocalIP(context.Background(), local), time.Second)
	defer cancel()
	c, err := (&Direct{}).DialContext(ctx, "tcp", M.SocksaddrFromNet(target.Addr()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	peer, err := target.Accept()
	if err != nil {
		t.Fatal(err)
	}
	peer.Close()
	if !ingress.AddressIP(c.LocalAddr()).Is6() {
		t.Fatal("cross-family fallback failed")
	}
}
func TestDirectUDPAssociationRetainsBothFamiliesAndDeadlines(t *testing.T) {
	source := localIPv4(t)
	v4, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer v4.Close()
	v6, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 loopback unavailable")
	}
	defer v6.Close()
	ctx := ingress.WithLocalIP(context.Background(), source)
	socket, err := (&Direct{}).ListenPacket(ctx, M.SocksaddrFromNet(v4.LocalAddr()))
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	for _, target := range []net.PacketConn{v4, v6, v4} {
		if _, err := socket.WriteTo([]byte("packet"), target.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		target.SetReadDeadline(time.Now().Add(time.Second))
		var b [16]byte
		n, remote, err := target.ReadFrom(b[:])
		if err != nil {
			t.Fatal(err)
		}
		want := source
		if target == v6 {
			want = netip.MustParseAddr("::1")
		}
		if got := ingress.AddressIP(remote); got != want {
			t.Fatal("wrong UDP source", got, want)
		}
		if _, err := target.WriteTo(b[:n], remote); err != nil {
			t.Fatal(err)
		}
		socket.SetReadDeadline(time.Now().Add(time.Second))
		if _, _, err := socket.ReadFrom(b[:]); err != nil {
			t.Fatal(err)
		}
	}
	socket.SetReadDeadline(time.Now().Add(-time.Second))
	var b [16]byte
	if _, _, err := socket.ReadFrom(b[:]); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("read deadline not honored", err)
	}
	socket.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := socket.WriteTo([]byte("after timeout"), v4.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	n, peer, err := v4.ReadFrom(b[:])
	if err != nil {
		t.Fatal(err)
	}
	v4.WriteTo(b[:n], peer)
	if _, _, err := socket.ReadFrom(b[:]); err != nil {
		t.Fatal("deadline reset did not recover", err)
	}
	done := make(chan struct{})
	go func() { socket.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("UDP readers survived close")
	}
	if _, _, err := socket.ReadFrom(b[:]); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed read did not fail", err)
	}
}

func TestIPv6OnlyNameFallsBackFromIPv4Ingress(t *testing.T) {
	local := localIPv4(t)
	target, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 loopback unavailable")
	}
	defer target.Close()
	dns, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		var raw [4096]byte
		for {
			n, from, e := dns.ReadFrom(raw[:])
			if e != nil {
				return
			}
			var request dnsmessage.Message
			if e = request.Unpack(raw[:n]); e != nil {
				continue
			}
			response := dnsmessage.Message{Header: dnsmessage.Header{ID: request.ID, Response: true, Authoritative: true, RecursionDesired: request.RecursionDesired, RecursionAvailable: true}, Questions: request.Questions}
			for _, q := range request.Questions {
				if q.Type == dnsmessage.TypeAAAA {
					response.Answers = append(response.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 1}, Body: &dnsmessage.AAAAResource{AAAA: [16]byte{15: 1}}})
				}
			}
			packet, e := response.Pack()
			if e == nil {
				_, _ = dns.WriteTo(packet, from)
			}
		}
	}()
	defer func() { dns.Close(); <-done }()
	d := &Direct{Dialer: net.Dialer{Resolver: &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", dns.LocalAddr().String())
	}}}}
	ctx, cancel := context.WithTimeout(ingress.WithLocalIP(context.Background(), local), 2*time.Second)
	defer cancel()
	destination := M.Socksaddr{Fqdn: "ipv6-only.test", Port: M.SocksaddrFromNet(target.Addr()).Port}
	c, err := d.DialContext(ctx, "tcp", destination)
	if err != nil {
		t.Fatal("IPv6-only DNS destination could not fall back", err)
	}
	defer c.Close()
	peer, err := target.Accept()
	if err != nil {
		t.Fatal(err)
	}
	peer.Close()
}
