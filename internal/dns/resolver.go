// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors
// Adapted from Polaris 56d52fb44958ef3cc2a7fb841cd240f8206234b2.
package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/route"
)

const (
	maxDNSMessage = 65535
	minTTL        = time.Second
	maxTTL        = 24 * time.Hour
	dnsTypeA      = 1
	dnsTypeAAAA   = 28
)

// Options controls bounded DNS requests.
type Options struct {
	Context         context.Context
	Timeout         time.Duration
	Preference      Preference
	SystemLookupTTL time.Duration
}

// Resolver resolves against atomically published immutable DNS snapshots.
type Resolver struct {
	ctx          context.Context
	cancel       context.CancelFunc
	lifeMu       sync.Mutex
	closed       bool
	active       sync.WaitGroup
	closeOnce    sync.Once
	snapshot     atomic.Pointer[Snapshot]
	timeout      time.Duration
	preference   Preference
	dialer       net.Dialer
	client       *http.Client
	dohClients   sync.Map
	systemCache  *addressCache
	systemLookup func(context.Context, string, string) ([]netip.Addr, error)
}

// NewResolver creates a resolver with an explicit request timeout.
func NewResolver(snapshot *Snapshot, options Options) *Resolver {
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	preference := options.Preference
	if preference == "" {
		preference = PreferIPv4
	}
	root := options.Context
	if root == nil {
		root = context.Background()
	}
	root, cancel := context.WithCancel(root)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.MaxConnsPerHost = 32
	resolver := &Resolver{ctx: root, cancel: cancel,
		timeout: timeout, preference: preference, client: &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		systemCache:  newAddressCache(options.SystemLookupTTL),
		systemLookup: net.DefaultResolver.LookupNetIP,
	}
	owned := *snapshot
	owned.cache = newCache()
	resolver.bindCache(owned.cache)
	resolver.bindSystemCache(resolver.systemCache)
	transport.DialContext = resolver.bootstrapDial
	resolver.snapshot.Store(&owned)
	return resolver
}

// Snapshot returns the active immutable DNS snapshot.
func (resolver *Resolver) Snapshot() *Snapshot { return resolver.snapshot.Load() }

// Replace validates fully before publishing a new generation-local cache.
func (resolver *Resolver) Replace(config Config) error {
	candidate, err := Compile(config)
	if err != nil {
		return err
	}
	resolver.lifeMu.Lock()
	defer resolver.lifeMu.Unlock()
	if resolver.closed || resolver.ctx.Err() != nil {
		return ErrClosed
	}
	resolver.bindCache(candidate.cache)
	resolver.snapshot.Store(candidate)
	return nil
}

// Lookup resolves A and AAAA records in the requested preference order.
func (resolver *Resolver) Lookup(ctx context.Context, name string, preference Preference) ([]netip.Addr, error) {
	ctx, finish, beginErr := resolver.begin(ctx)
	if beginErr != nil {
		return nil, beginErr
	}
	defer finish()
	if preference == OnlyIPv4 {
		return resolver.lookupType(ctx, name, dnsTypeA)
	}
	if preference == OnlyIPv6 {
		return resolver.lookupType(ctx, name, dnsTypeAAAA)
	}
	first, second := uint16(dnsTypeA), uint16(dnsTypeAAAA)
	if preference == PreferIPv6 {
		first, second = second, first
	}
	addresses, err := resolver.lookupType(ctx, name, first)
	if err != nil {
		return nil, err
	}
	other, otherErr := resolver.lookupType(ctx, name, second)
	if otherErr == nil {
		addresses = append(addresses, other...)
	}
	if len(addresses) == 0 && otherErr != nil {
		return nil, otherErr
	}
	return addresses, nil
}

// LookupIP implements route.NameResolver with the configured IP strategy.
func (resolver *Resolver) LookupIP(ctx context.Context, name string) ([]netip.Addr, error) {
	ctx, finish, beginErr := resolver.begin(ctx)
	if beginErr != nil {
		return nil, beginErr
	}
	defer finish()
	addresses, err := resolver.Lookup(ctx, name, resolver.preference)
	if !errors.Is(err, ErrNoConfiguredResolver) {
		return addresses, err
	}
	network := "ip"
	switch resolver.preference {
	case OnlyIPv4:
		network = "ip4"
	case OnlyIPv6:
		network = "ip6"
	default:
		// The prefer strategies query both families and order the answers.
	}
	cacheKey := network + "\x00" + strings.ToLower(strings.TrimSuffix(name, "."))
	addresses, err = resolver.systemCache.lookup(ctx, cacheKey, func(ctx context.Context) ([]netip.Addr, error) {
		return resolver.systemLookup(ctx, network, name)
	})
	if err != nil {
		return addresses, err
	}
	for index := range addresses {
		addresses[index] = addresses[index].Unmap()
	}
	if resolver.preference == OnlyIPv4 || resolver.preference == OnlyIPv6 {
		return addresses, nil
	}
	preferIPv6 := resolver.preference == PreferIPv6
	ordered := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		if address.Is6() == preferIPv6 {
			ordered = append(ordered, address)
		}
	}
	for _, address := range addresses {
		if address.Is6() != preferIPv6 {
			ordered = append(ordered, address)
		}
	}
	return ordered, nil
}

// ExchangePacket implements route.DNSPacketExchanger for proxied UDP/53 traffic.
func (resolver *Resolver) ExchangePacket(ctx context.Context, query []byte) ([]byte, error) {
	ctx, finish, beginErr := resolver.begin(ctx)
	if beginErr != nil {
		return nil, beginErr
	}
	defer finish()
	if len(query) < 12 || len(query) > maxDNSMessage || query[2]&0xf8 != 0 {
		return nil, errMalformedMessage
	}
	name, _, queryClass, err := queryNameAndType(query)
	if err != nil || queryClass != 1 {
		return nil, errMalformedMessage
	}
	ctx, cancel := context.WithTimeout(ctx, resolver.timeout)
	defer cancel()
	server, err := resolver.Snapshot().selectServer(name)
	if errors.Is(err, ErrNoConfiguredResolver) {
		return nil, route.ErrNoDNSResolverMatch
	}
	if err != nil {
		return nil, err
	}
	response, err := resolver.exchange(ctx, server, query)
	if err != nil {
		return nil, err
	}
	if err = validateResponse(query, response); err != nil {
		return nil, err
	}
	return response, nil
}

func (resolver *Resolver) lookupType(ctx context.Context, name string, qType uint16) ([]netip.Addr, error) {
	response, err := resolver.Exchange(ctx, name, qType)
	if err != nil {
		return nil, err
	}
	return parseAddresses(response, qType)
}

// Exchange sends one bounded DNS query using the selected configured server.
func (resolver *Resolver) Exchange(ctx context.Context, name string, qType uint16) ([]byte, error) {
	ctx, finish, beginErr := resolver.begin(ctx)
	if beginErr != nil {
		return nil, beginErr
	}
	defer finish()
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if name == "" {
		return nil, errors.New("dns: empty query name")
	}
	ctx, cancel := context.WithTimeout(ctx, resolver.timeout)
	defer cancel()
	snapshot := resolver.Snapshot()
	// The closure runs only on a miss, so a cache hit still avoids building a
	// query and selecting a server.
	return snapshot.cache.lookup(ctx, cacheKey{name: name, qType: qType},
		func(ctx context.Context) ([]byte, time.Duration, error) {
			return resolver.exchangeUncached(ctx, snapshot, name, qType)
		})
}

// exchangeUncached performs one upstream exchange and reports the TTL the caller
// should cache it for. A zero TTL means the response must not be cached.
func (resolver *Resolver) exchangeUncached(
	ctx context.Context, snapshot *Snapshot, name string, qType uint16,
) ([]byte, time.Duration, error) {
	query, err := makeQuery(name, qType)
	if err != nil {
		return nil, 0, err
	}
	server, err := snapshot.selectServer(name)
	if err != nil {
		return nil, 0, err
	}
	response, err := resolver.exchange(ctx, server, query)
	if err != nil {
		return nil, 0, err
	}
	if err := validateResponse(query, response); err != nil {
		return nil, 0, err
	}
	if len(response) > maxDNSMessage {
		return nil, 0, fmt.Errorf("dns: response exceeds %d bytes", maxDNSMessage)
	}
	ttl, err := cacheTTL(response)
	if err != nil {
		return nil, 0, err
	}
	if ttl <= 0 {
		return response, 0, nil
	}
	return response, boundTTL(ttl), nil
}

func boundTTL(ttl time.Duration) time.Duration {
	if ttl < minTTL {
		return minTTL
	}
	if ttl > maxTTL {
		return maxTTL
	}
	return ttl
}

func deadline(ctx context.Context) time.Time {
	value, ok := ctx.Deadline()
	if ok {
		return value
	}
	return time.Now()
}

// Close cancels active sockets and joined queries before releasing HTTP pools.
func (r *Resolver) Close() {
	r.closeOnce.Do(func() {
		r.lifeMu.Lock()
		r.closed = true
		r.cancel()
		r.lifeMu.Unlock()
		r.active.Wait()
		r.client.CloseIdleConnections()
		r.dohClients.Range(func(_, v any) bool { v.(*http.Client).CloseIdleConnections(); return true })
	})
}
func (r *Resolver) begin(ctx context.Context) (context.Context, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	r.lifeMu.Lock()
	if r.closed || r.ctx.Err() != nil {
		r.lifeMu.Unlock()
		return nil, nil, ErrClosed
	}
	r.active.Add(1)
	r.lifeMu.Unlock()
	work, cancel := context.WithTimeout(ctx, r.timeout)
	stop := context.AfterFunc(r.ctx, cancel)
	return work, func() { stop(); cancel(); r.active.Done() }, nil
}
func (r *Resolver) start(work func()) bool {
	r.lifeMu.Lock()
	defer r.lifeMu.Unlock()
	if r.closed || r.ctx.Err() != nil {
		return false
	}
	r.active.Add(1)
	go func() { defer r.active.Done(); work() }()
	return true
}
func (r *Resolver) workContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.ctx, r.timeout)
}
func (r *Resolver) bindCache(c *cache)              { c.start = r.start; c.workContext = r.workContext }
func (r *Resolver) bindSystemCache(c *addressCache) { c.start = r.start; c.workContext = r.workContext }
