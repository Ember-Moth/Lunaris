// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors
// Adapted from Polaris 56d52fb44958ef3cc2a7fb841cd240f8206234b2.
package dns

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/route"
)

func TestConfig_rejects_QUIC_and_preserves_active_snapshot(t *testing.T) {
	// Given
	resolver := NewResolver(MustCompile(Config{}), Options{Timeout: time.Second})
	before := resolver.Snapshot().Hash()

	// When
	err := resolver.Replace(Config{Servers: []model.DNSServer{{Proto: "quic", Address: "dns.example"}}})

	// Then
	if err == nil {
		t.Fatal("expected QUIC DNS rejection")
	}
	if got := resolver.Snapshot().Hash(); got != before {
		t.Fatalf("active snapshot hash = %q, want %q", got, before)
	}
}

func TestResolver_respects_context_deadline(t *testing.T) {
	// Given
	resolver := NewResolver(MustCompile(Config{Servers: []model.DNSServer{{Proto: "udp", Address: "192.0.2.1:53"}}}), Options{Timeout: time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()

	// When
	_, err := resolver.Lookup(ctx, "example.com", PreferIPv4)

	// Then
	if err == nil {
		t.Fatal("expected deadline error")
	}
}

func TestRoutingDNSFailureMatrix(t *testing.T) {
	// Given
	active := MustCompile(Config{Servers: []model.DNSServer{{Proto: "udp", Address: "127.0.0.1:53", Domains: []string{"suffix:example.com"}}}})
	resolver := NewResolver(active, Options{Timeout: time.Second})

	// When / Then
	for _, config := range []Config{
		{Servers: []model.DNSServer{{Proto: "quic", Address: "dns.example:853"}}},
		{Servers: []model.DNSServer{{Proto: "udp", Address: "127.0.0.1:53", Domains: []string{"regex:("}}}},
	} {
		before := resolver.Snapshot().Hash()
		if err := resolver.Replace(config); err == nil {
			t.Fatal("expected invalid DNS configuration")
		}
		if got := resolver.Snapshot().Hash(); got != before {
			t.Fatalf("active snapshot hash = %q, want %q", got, before)
		}
	}
}

func TestCompileAcceptsDoHHostname(t *testing.T) {
	_, err := Compile(Config{Servers: []model.DNSServer{{Proto: "https", Address: "https://dns.example/dns-query"}}})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
}

func TestDoHClientUsesConfiguredServerName(t *testing.T) {
	resolver := NewResolver(MustCompile(Config{}), Options{})
	client := resolver.dohClient(server{transport: transportHTTPS, address: "https://127.0.0.1/dns-query", serverName: "dns.example"})
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil || transport.TLSClientConfig.ServerName != "dns.example" {
		t.Fatalf("DoH transport = %#v, want configured TLS server name", client.Transport)
	}
	transport.CloseIdleConnections()
}

func TestLookupIPFallsBackToSystemResolverWithoutMatchingPanelServer(t *testing.T) {
	resolver := NewResolver(MustCompile(Config{Servers: []model.DNSServer{{
		Proto: "udp", Address: "127.0.0.1:53", Domains: []string{"full:panel-only.example"},
	}}}), Options{Preference: PreferIPv4})
	addresses, err := resolver.LookupIP(context.Background(), "localhost")
	if err != nil {
		t.Fatalf("LookupIP() error = %v", err)
	}
	if len(addresses) == 0 || !containsLoopback(addresses) {
		t.Fatalf("LookupIP() = %v, want a system loopback address", addresses)
	}
}

func TestLookupIPCachesAndOrdersSystemResults(t *testing.T) {
	for _, test := range []struct {
		name       string
		preference Preference
		network    string
		want       []netip.Addr
	}{
		{
			name: "prefer IPv4", preference: PreferIPv4, network: "ip",
			want: []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")},
		},
		{
			name: "prefer IPv6", preference: PreferIPv6, network: "ip",
			want: []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("192.0.2.1")},
		},
		{
			name: "only IPv4", preference: OnlyIPv4, network: "ip4",
			want: []netip.Addr{netip.MustParseAddr("192.0.2.1")},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolver := NewResolver(MustCompile(Config{}), Options{Preference: test.preference})
			var calls atomic.Int32
			resolver.systemLookup = func(_ context.Context, network, _ string) ([]netip.Addr, error) {
				calls.Add(1)
				if network != test.network {
					t.Fatalf("lookup network = %q, want %q", network, test.network)
				}
				if network == "ip4" {
					return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
				}
				return []netip.Addr{
					netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("192.0.2.1"),
				}, nil
			}

			first, err := resolver.LookupIP(context.Background(), "Target.Example")
			if err != nil {
				t.Fatal(err)
			}
			second, err := resolver.LookupIP(context.Background(), "target.example.")
			if err != nil {
				t.Fatal(err)
			}
			if !equalAddresses(first, test.want) || !equalAddresses(second, test.want) {
				t.Fatalf("LookupIP() = %v, %v, want %v", first, second, test.want)
			}
			if count := calls.Load(); count != 1 {
				t.Fatalf("system lookup count = %d, want 1", count)
			}
		})
	}
}

func TestLookupIPCoalescesConcurrentSystemQueries(t *testing.T) {
	resolver := NewResolver(MustCompile(Config{}), Options{Preference: PreferIPv4})
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	resolver.systemLookup = func(context.Context, string, string) ([]netip.Addr, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil
	}

	const goroutines = 32
	var wait sync.WaitGroup
	errors := make(chan error, goroutines)
	for range goroutines {
		wait.Go(func() {
			_, err := resolver.LookupIP(context.Background(), "burst.example")
			errors <- err
		})
	}
	<-started
	close(release)
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	if count := calls.Load(); count != 1 {
		t.Fatalf("system lookup count = %d, want 1", count)
	}
}

func TestLookupIPDoesNotCacheSystemFailures(t *testing.T) {
	resolver := NewResolver(MustCompile(Config{}), Options{})
	var calls atomic.Int32
	resolver.systemLookup = func(context.Context, string, string) ([]netip.Addr, error) {
		calls.Add(1)
		return nil, errors.New("lookup failed")
	}
	for range 2 {
		if _, err := resolver.LookupIP(context.Background(), "failure.example"); err == nil {
			t.Fatal("expected lookup failure")
		}
	}
	if count := calls.Load(); count != 2 {
		t.Fatalf("system lookup count = %d, want 2", count)
	}
}

func TestLookupIPExpiresSystemResults(t *testing.T) {
	resolver := NewResolver(MustCompile(Config{}), Options{SystemLookupTTL: time.Nanosecond})
	var calls atomic.Int32
	resolver.systemLookup = func(context.Context, string, string) ([]netip.Addr, error) {
		calls.Add(1)
		return []netip.Addr{netip.MustParseAddr("192.0.2.20")}, nil
	}
	for range 2 {
		if _, err := resolver.LookupIP(context.Background(), "expiring.example"); err != nil {
			t.Fatal(err)
		}
	}
	if count := calls.Load(); count != 2 {
		t.Fatalf("system lookup count = %d, want 2 after TTL expiry", count)
	}
}

func equalAddresses(left, right []netip.Addr) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func TestExchangePacketSignalsUnmatchedPanelDNSRule(t *testing.T) {
	resolver := NewResolver(MustCompile(Config{Servers: []model.DNSServer{{
		Proto: "udp", Address: "127.0.0.1:53", Domains: []string{"full:panel-only.example"},
	}}}), Options{})
	query, err := makeQuery("unmatched.example", dnsTypeA)
	if err != nil {
		t.Fatal(err)
	}
	_, err = resolver.ExchangePacket(context.Background(), query)
	if !errors.Is(err, route.ErrNoDNSResolverMatch) {
		t.Fatalf("ExchangePacket() error = %v, want no resolver match", err)
	}
}

func containsLoopback(addresses []netip.Addr) bool {
	for _, address := range addresses {
		if address.IsLoopback() {
			return true
		}
	}
	return false
}

func TestParsePreferenceAcceptsPPanelAndXraySpellings(t *testing.T) {
	for input, expected := range map[string]Preference{
		"prefer_ipv4": PreferIPv4,
		"PreferIPv6":  PreferIPv6,
		"UseIPv4":     OnlyIPv4,
		"ipv6_only":   OnlyIPv6,
		"UseIPv4v6":   PreferIPv4,
		"UseIPv6v4":   PreferIPv6,
	} {
		actual, err := ParsePreference(input)
		if err != nil || actual != expected {
			t.Fatalf("ParsePreference(%q) = (%q, %v), want %q", input, actual, err, expected)
		}
	}
}

func TestCompile_accepts_hostname_and_rejects_IP_only_DoT(t *testing.T) {
	// Given
	hostname := Config{Servers: []model.DNSServer{{Proto: "dot", Address: "dns.example:853"}}}
	ipOnly := Config{Servers: []model.DNSServer{{Proto: "dot", Address: "192.0.2.1:853"}}}
	ipWithName := Config{Servers: []model.DNSServer{{Proto: "dot", Address: "192.0.2.1:853", ServerName: "dns.example"}}}

	// When
	snapshot, hostnameErr := Compile(hostname)
	_, ipOnlyErr := Compile(ipOnly)
	ipWithNameSnapshot, ipWithNameErr := Compile(ipWithName)

	// Then
	if hostnameErr != nil {
		t.Fatalf("compile hostname DoT: %v", hostnameErr)
	}
	if ipOnlyErr == nil {
		t.Fatal("expected IP-only DoT rejection")
	}
	if ipWithNameErr != nil {
		t.Fatalf("compile IP DoT with explicit server name: %v", ipWithNameErr)
	}
	server, err := snapshot.selectServer("example.com")
	if err != nil {
		t.Fatalf("select DoT server: %v", err)
	}
	if server.serverName != "dns.example" {
		t.Fatalf("DoT server name = %q, want %q", server.serverName, "dns.example")
	}
	ipWithNameServer, err := ipWithNameSnapshot.selectServer("example.com")
	if err != nil {
		t.Fatalf("select IP DoT server: %v", err)
	}
	if ipWithNameServer.serverName != "dns.example" {
		t.Fatalf("IP DoT server name = %q, want %q", ipWithNameServer.serverName, "dns.example")
	}
}
