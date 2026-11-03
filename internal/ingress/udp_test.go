//go:build linux || darwin

// SPDX-License-Identifier: GPL-3.0-only
package ingress

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

func localIPv4(t *testing.T) netip.Addr {
	t.Helper()
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err != nil {
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
func TestWildcardUDPArrivalAddressAndResponseSource(t *testing.T) {
	ip := localIPv4(t)
	raw, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	conn, err := PacketConn(raw)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	port := raw.LocalAddr().(*net.UDPAddr).Port
	for _, destination := range []netip.Addr{netip.MustParseAddr("127.0.0.1"), ip} {
		target := net.UDPAddrFromAddrPort(netip.AddrPortFrom(destination, uint16(port)))
		if _, err := peer.WriteTo([]byte("request"), target); err != nil {
			t.Fatal(err)
		}
		conn.SetReadDeadline(time.Now().Add(time.Second))
		var data [64]byte
		n, remote, local, err := ReadPacket(conn, data[:])
		if err != nil {
			t.Fatal(err)
		}
		if AddressIP(local) != destination {
			t.Fatal("wrong local destination", local, target)
		}
		if _, err := WritePacket(conn, data[:n], remote, local); err != nil {
			t.Fatal(err)
		}
		peer.SetReadDeadline(time.Now().Add(time.Second))
		_, from, err := peer.ReadFrom(data[:])
		if err != nil {
			t.Fatal(err)
		}
		if AddressIP(from) != destination {
			t.Fatal("reply source changed", from, target)
		}
	}
}
func TestLocalContextSurvivesLogicalStreams(t *testing.T) {
	first := netip.MustParseAddr("198.18.0.1")
	ctx := WithLocalIP(context.Background(), first)
	if ip, _ := LocalIP(WithLocalIP(ctx, netip.MustParseAddr("198.18.0.2"))); ip != first {
		t.Fatal("nested context overwrote ingress")
	}
	ctx, slot := WithLocalSlot(context.Background())
	slot.Set(net.UDPAddrFromAddrPort(netip.AddrPortFrom(first, 443)))
	if ip, _ := LocalIP(ctx); ip != first {
		t.Fatal("QUIC endpoint slot lost")
	}
}
