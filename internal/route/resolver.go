// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors
// Adapted from Polaris 56d52fb44958ef3cc2a7fb841cd240f8206234b2.
package route

import (
	"context"
	"errors"
	"net/netip"
)

// ErrNoDNSResolverMatch identifies a query that no configured resolver domain
// covers.
var ErrNoDNSResolverMatch = errors.New("route: no configured DNS resolver matches the query")

// NameResolver is the generation-local DNS boundary used by direct outbounds.
// Ownership of a successful result transfers to the caller; implementations
// must not retain and later mutate the returned slice.
type NameResolver interface {
	LookupIP(context.Context, string) ([]netip.Addr, error)
}

// DNSPacketExchanger resolves one raw DNS message through configured panel upstreams.
type DNSPacketExchanger interface {
	ExchangePacket(context.Context, []byte) ([]byte, error)
}

type (
	resolverContextKey          struct{}
	resolvedAddressesContextKey struct{}
)

type resolvedAddresses struct {
	host      string
	addresses []netip.Addr
}

// WithNameResolver attaches a generation-local resolver without changing callers that use system DNS.
func WithNameResolver(ctx context.Context, resolver NameResolver) context.Context {
	if resolver == nil {
		return ctx
	}
	return context.WithValue(ctx, resolverContextKey{}, resolver)
}

func NameResolverFromContext(ctx context.Context) NameResolver {
	resolver, _ := ctx.Value(resolverContextKey{}).(NameResolver)
	return resolver
}

// WithResolvedAddresses makes addresses already obtained for route selection
// available to a direct outbound, avoiding a second DNS query. It retains an
// already-valid, unmapped slice, so callers must not mutate addresses afterwards.
func WithResolvedAddresses(ctx context.Context, host string, addresses []netip.Addr) context.Context {
	host = normalizeDomain(host)
	if ctx == nil {
		ctx = context.Background()
	}
	if host == "" || len(addresses) == 0 {
		return ctx
	}
	valid := addresses
	for _, address := range addresses {
		if !address.IsValid() || address.Is4In6() {
			valid = make([]netip.Addr, 0, len(addresses))
			for _, candidate := range addresses {
				if candidate.IsValid() {
					valid = append(valid, candidate.Unmap())
				}
			}
			break
		}
	}
	if len(valid) == 0 {
		return ctx
	}
	return context.WithValue(ctx, resolvedAddressesContextKey{}, resolvedAddresses{host: host, addresses: valid})
}

func ResolvedAddressesFromContext(ctx context.Context, host string) ([]netip.Addr, bool) {
	if ctx == nil {
		return nil, false
	}
	resolved, _ := ctx.Value(resolvedAddressesContextKey{}).(resolvedAddresses)
	if resolved.host != normalizeDomain(host) || len(resolved.addresses) == 0 {
		return nil, false
	}
	return resolved.addresses, true
}

func DNSPacketExchangerFromContext(ctx context.Context) DNSPacketExchanger {
	if enabled, _ := ctx.Value(dnsHijackKey{}).(bool); !enabled {
		return nil
	}
	resolver, _ := ctx.Value(resolverContextKey{}).(DNSPacketExchanger)
	return resolver
}

type dnsHijackKey struct{}

func WithDNSHijack(ctx context.Context, enabled bool) context.Context {
	return context.WithValue(ctx, dnsHijackKey{}, enabled)
}

type Target string

const (
	Direct Target = "direct"
	Block  Target = "block"
	DNS    Target = "dns"
)

// WithoutNameResolver breaks DNS bootstrap recursion while preserving ingress values.
func WithoutNameResolver(ctx context.Context) context.Context {
	return context.WithValue(ctx, resolverContextKey{}, struct{}{})
}
