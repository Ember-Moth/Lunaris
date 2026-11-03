// SPDX-License-Identifier: GPL-3.0-only
// Package ingress carries the original local endpoint across protocol wrappers.
package ingress

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
)

type localKey struct{}
type pendingKey struct{}
type peerKey struct{}

// WithPeer retains the socket peer separately from untrusted PROXY addresses.
func WithPeer(ctx context.Context, address net.Addr) context.Context {
	return WithPeerIP(ctx, AddressIP(address))
}

func WithPeerIP(ctx context.Context, ip netip.Addr) context.Context {
	if _, ok := ctx.Value(peerKey{}).(netip.Addr); ok {
		return ctx
	}
	return context.WithValue(ctx, peerKey{}, ip.Unmap())
}

func PeerIP(ctx context.Context, fallback net.Addr) netip.Addr {
	if ip, ok := ctx.Value(peerKey{}).(netip.Addr); ok {
		return ip
	}
	return AddressIP(fallback)
}

// LocalSlot attaches the physical endpoint when QUIC accepts a connection.
// Stream contexts inherit this slot even when the protocol uses a service context.
type LocalSlot struct{ address atomic.Pointer[netip.Addr] }

func WithLocalSlot(ctx context.Context) (context.Context, *LocalSlot) {
	slot := new(LocalSlot)
	return context.WithValue(ctx, pendingKey{}, slot), slot
}
func (s *LocalSlot) Set(address net.Addr) {
	if ip := AddressIP(address); validLocal(ip) {
		s.address.CompareAndSwap(nil, &ip)
	}
}
func LocalIP(ctx context.Context) (netip.Addr, bool) {
	if ctx == nil {
		return netip.Addr{}, false
	}
	if ip, ok := ctx.Value(localKey{}).(netip.Addr); ok {
		return ip, true
	}
	if slot, ok := ctx.Value(pendingKey{}).(*LocalSlot); ok {
		if ip := slot.address.Load(); ip != nil {
			return *ip, true
		}
	}
	return netip.Addr{}, false
}
func validLocal(ip netip.Addr) bool { return ip.IsValid() && !ip.IsUnspecified() && !ip.IsMulticast() }
func AddressIP(address net.Addr) netip.Addr {
	if address == nil {
		return netip.Addr{}
	}
	if addr, err := netip.ParseAddrPort(address.String()); err == nil {
		return addr.Addr().Unmap()
	}
	if ip, err := netip.ParseAddr(address.String()); err == nil {
		return ip.Unmap()
	}
	return netip.Addr{}
}

// WithLocalIP keeps the first concrete carrier address. Mux/UoT and logical
// protocol streams must not overwrite it with a target or a client address.
func WithLocalIP(ctx context.Context, ip netip.Addr) context.Context {
	if _, ok := LocalIP(ctx); ok {
		return ctx
	}
	ip = ip.Unmap()
	if !validLocal(ip) {
		return ctx
	}
	return context.WithValue(ctx, localKey{}, ip)
}
func WithLocal(ctx context.Context, address net.Addr) context.Context {
	return WithLocalIP(ctx, AddressIP(address))
}

// StreamContext recovers the parent QUIC context exposed by embedded Streams.
func StreamContext(ctx context.Context, c net.Conn) context.Context {
	if _, ok := LocalIP(ctx); ok {
		return ctx
	}
	// TUIC can wrap a QUIC stream in a CachedConn. Inspect only metadata;
	// never unwrap the actual reader and bypass its buffered application bytes.
	var current any = c
	for range 16 {
		if contextual, ok := current.(interface{ Context() context.Context }); ok {
			if ip, ok := LocalIP(contextual.Context()); ok {
				return WithLocalIP(ctx, ip)
			}
		}
		upstream, ok := current.(interface{ Upstream() any })
		if !ok {
			break
		}
		current = upstream.Upstream()
	}
	// Some protocol streams call the requested target their LocalAddr and
	// report no RemoteAddr. Such a logical target is not an ingress endpoint.
	if AddressIP(c.RemoteAddr()).IsValid() {
		return WithLocal(ctx, c.LocalAddr())
	}
	return ctx
}

// BindingIP excludes local-only carrier addresses, matching Polaris's default
// direct-outbound policy. They must not pin Internet dials to loopback or a link.
func BindingIP(ctx context.Context) (netip.Addr, bool) {
	ip, ok := LocalIP(ctx)
	return ip, ok && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}
