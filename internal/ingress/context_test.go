// SPDX-License-Identifier: GPL-3.0-only
package ingress

import (
	"context"
	"net"
	"net/netip"
	"testing"
)

func TestPeerContextPreservesSocketSource(t *testing.T) {
	physical := netip.MustParseAddr("127.0.0.1")
	declared := netip.MustParseAddr("127.0.0.2")
	ctx := WithPeer(context.Background(), &net.TCPAddr{IP: net.IP(physical.AsSlice()), Port: 1000})
	ctx = WithPeerIP(ctx, declared)
	if got := PeerIP(ctx, &net.TCPAddr{IP: net.IP(declared.AsSlice())}); got != physical {
		t.Fatal(got)
	}
	if got := PeerIP(context.Background(), &net.TCPAddr{IP: net.IP(declared.AsSlice())}); got != declared {
		t.Fatal("fallback", got)
	}
}
