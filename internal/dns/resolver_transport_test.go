// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors
// Adapted from Polaris 56d52fb44958ef3cc2a7fb841cd240f8206234b2.
package dns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
)

func TestResolver_rejects_truncated_UDP_response(t *testing.T) {
	// Given
	address := startUDPServer(t, func(query []byte) []byte {
		response := makeResponse(query, nil)
		response[2] |= 0x02
		return response
	})
	resolver := NewResolver(MustCompile(Config{Servers: []model.DNSServer{{Proto: "udp", Address: address}}}), Options{Timeout: time.Second})

	// When
	_, err := resolver.Exchange(context.Background(), "example.com", dnsTypeA)

	// Then
	if !errors.Is(err, ErrTruncatedResponse) {
		t.Fatalf("Exchange error = %v, want truncated response", err)
	}
}

func TestResolver_caches_NXDOMAIN_but_not_SERVFAIL(t *testing.T) {
	// Given
	var nxDomainCalls atomic.Int32
	nxDomainAddress := startUDPServer(t, func(query []byte) []byte {
		nxDomainCalls.Add(1)
		response := makeResponse(query, nil)
		response[3] = 3
		return response
	})
	nxDomainResolver := NewResolver(MustCompile(Config{Servers: []model.DNSServer{{Proto: "udp", Address: nxDomainAddress}}}), Options{Timeout: time.Second})

	var serverFailureCalls atomic.Int32
	serverFailureAddress := startUDPServer(t, func(query []byte) []byte {
		serverFailureCalls.Add(1)
		response := makeResponse(query, nil)
		response[3] = 2
		return response
	})
	serverFailureResolver := NewResolver(MustCompile(Config{Servers: []model.DNSServer{{Proto: "udp", Address: serverFailureAddress}}}), Options{Timeout: time.Second})

	// When
	_, firstNXDomainErr := nxDomainResolver.Exchange(context.Background(), "missing.example", dnsTypeA)
	_, secondNXDomainErr := nxDomainResolver.Exchange(context.Background(), "missing.example", dnsTypeA)
	_, firstServerFailureErr := serverFailureResolver.Exchange(context.Background(), "broken.example", dnsTypeA)
	_, secondServerFailureErr := serverFailureResolver.Exchange(context.Background(), "broken.example", dnsTypeA)

	// Then
	if firstNXDomainErr != nil || secondNXDomainErr != nil {
		t.Fatalf("NXDOMAIN errors = (%v, %v)", firstNXDomainErr, secondNXDomainErr)
	}
	if got := nxDomainCalls.Load(); got != 1 {
		t.Fatalf("NXDOMAIN requests = %d, want 1", got)
	}
	if firstServerFailureErr == nil || secondServerFailureErr == nil {
		t.Fatalf("SERVFAIL errors = (%v, %v), want two errors", firstServerFailureErr, secondServerFailureErr)
	}
	if got := serverFailureCalls.Load(); got != 2 {
		t.Fatalf("SERVFAIL requests = %d, want 2", got)
	}
}

func TestResolver_caches_NODATA(t *testing.T) {
	// Given
	var calls atomic.Int32
	address := startUDPServer(t, func(query []byte) []byte {
		calls.Add(1)
		return makeResponse(query, nil)
	})
	resolver := NewResolver(MustCompile(Config{Servers: []model.DNSServer{{Proto: "udp", Address: address}}}), Options{Timeout: time.Second})

	// When
	_, firstErr := resolver.Exchange(context.Background(), "empty.example", dnsTypeA)
	_, secondErr := resolver.Exchange(context.Background(), "empty.example", dnsTypeA)

	// Then
	if firstErr != nil || secondErr != nil {
		t.Fatalf("NODATA errors = (%v, %v)", firstErr, secondErr)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("NODATA requests = %d, want 1", got)
	}
}

func TestResolver_interrupts_UDP_read_when_context_is_canceled(t *testing.T) {
	// Given
	received := make(chan struct{}, 1)
	address := startUDPServer(t, func([]byte) []byte {
		received <- struct{}{}
		return nil
	})
	resolver := NewResolver(MustCompile(Config{Servers: []model.DNSServer{{Proto: "udp", Address: address}}}), Options{Timeout: 5 * time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := resolver.Exchange(ctx, "example.com", dnsTypeA)
		result <- err
	}()

	select {
	case <-received:
	case <-time.After(time.Second):
		t.Fatal("UDP server did not receive query")
	}

	// When
	cancel()

	// Then
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Exchange error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("UDP read did not stop after context cancellation")
	}
}

func TestResolver_rejects_unmatched_name_without_configured_default(t *testing.T) {
	// Given
	resolver := NewResolver(MustCompile(Config{Servers: []model.DNSServer{{
		Proto:   "udp",
		Address: "127.0.0.1:53",
		Domains: []string{"full:configured.example"},
	}}}), Options{Timeout: time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// When
	_, err := resolver.Exchange(ctx, "unmatched.example", dnsTypeA)

	// Then
	if !errors.Is(err, ErrNoConfiguredResolver) {
		t.Fatalf("Exchange error = %v, want no configured resolver", err)
	}
}

func startUDPServer(t *testing.T, respond func([]byte) []byte) string {
	t.Helper()
	connection, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	go func() {
		buffer := make([]byte, maxDNSMessage)
		for {
			count, peer, readErr := connection.ReadFrom(buffer)
			if readErr != nil {
				return
			}
			response := respond(append([]byte(nil), buffer[:count]...))
			if response == nil {
				continue
			}
			if _, writeErr := connection.WriteTo(response, peer); writeErr != nil {
				return
			}
		}
	}()
	return connection.LocalAddr().String()
}

// A burst of identical queries must reach the upstream once. Routing resolves a
// domain only when an IP rule could still win, and the prefer strategies issue
// both an A and an AAAA query, so a popular name whose entry has just expired
// would otherwise send two queries per new connection at the same server.
func TestExchangeCoalescesConcurrentQueries(t *testing.T) {
	// Given
	var calls atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	address := startUDPServer(t, func(query []byte) []byte {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return makeResponse(query, []netip.Addr{netip.MustParseAddr("192.0.2.10")})
	})
	resolver := NewResolver(
		MustCompile(Config{Servers: []model.DNSServer{{Proto: "udp", Address: address}}}),
		Options{Timeout: 5 * time.Second},
	)

	// When
	const goroutines = 32
	var wait sync.WaitGroup
	failures := make(chan error, goroutines)
	for range goroutines {
		wait.Go(func() {
			if _, err := resolver.Exchange(context.Background(), "burst.example", dnsTypeA); err != nil {
				failures <- err
			}
		})
	}
	<-started
	close(release)
	wait.Wait()
	close(failures)

	// Then
	for err := range failures {
		t.Fatalf("Exchange error = %v", err)
	}
	if count := calls.Load(); count != 1 {
		t.Fatalf("upstream query count = %d, want 1", count)
	}
}

// Coalescing must not be mistaken for caching: a second query after the first
// completes has to be served from the entry rather than reaching the upstream.
func TestExchangeStillCachesAfterCoalescing(t *testing.T) {
	// Given
	var calls atomic.Int32
	address := startUDPServer(t, func(query []byte) []byte {
		calls.Add(1)
		return makeResponse(query, []netip.Addr{netip.MustParseAddr("192.0.2.10")})
	})
	resolver := NewResolver(
		MustCompile(Config{Servers: []model.DNSServer{{Proto: "udp", Address: address}}}),
		Options{Timeout: time.Second},
	)

	// When
	for range 4 {
		if _, err := resolver.Exchange(context.Background(), "cached.example", dnsTypeA); err != nil {
			t.Fatalf("Exchange error = %v", err)
		}
	}

	// Then
	if count := calls.Load(); count != 1 {
		t.Fatalf("upstream query count = %d, want 1", count)
	}
}

// A failure is shared by the waiters that joined it, but must not be cached: the
// next caller has to get a fresh attempt.
func TestExchangeSharesFailureWithoutCachingIt(t *testing.T) {
	// Given
	var calls atomic.Int32
	release := make(chan struct{})
	started := make(chan struct{})
	address := startUDPServer(t, func(query []byte) []byte {
		if calls.Add(1) == 1 {
			close(started)
			<-release
		}
		response := makeResponse(query, nil)
		response[3] = 2 // SERVFAIL is not cacheable
		return response
	})
	resolver := NewResolver(
		MustCompile(Config{Servers: []model.DNSServer{{Proto: "udp", Address: address}}}),
		Options{Timeout: 5 * time.Second},
	)

	// When
	const goroutines = 8
	var wait sync.WaitGroup
	for range goroutines {
		wait.Go(func() {
			_, _ = resolver.Exchange(context.Background(), "broken.example", dnsTypeA)
		})
	}
	<-started
	// The leader is blocked upstream; wait until every other caller has joined
	// it before releasing, otherwise a late caller would legitimately start a
	// second exchange and the assertion below would measure scheduling instead
	// of sharing.
	key := cacheKey{name: "broken.example", qType: dnsTypeA}
	deadline := time.Now().Add(5 * time.Second)
	for resolver.Snapshot().cache.joined(key) < goroutines-1 {
		if time.Now().After(deadline) {
			t.Fatalf("only %d callers joined the in-flight exchange", resolver.Snapshot().cache.joined(key))
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	wait.Wait()
	duringBurst := calls.Load()
	_, _ = resolver.Exchange(context.Background(), "broken.example", dnsTypeA)

	// Then
	if duringBurst != 1 {
		t.Fatalf("upstream queries during burst = %d, want 1", duringBurst)
	}
	if total := calls.Load(); total != 2 {
		t.Fatalf("upstream queries after the burst = %d, want 2 (the failure must not be cached)", total)
	}
}
