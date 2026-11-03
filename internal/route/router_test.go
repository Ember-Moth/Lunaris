// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors
// Adapted from Polaris 56d52fb44958ef3cc2a7fb841cd240f8206234b2.
package route

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
)

type routingNameResolver struct {
	addresses []netip.Addr
	err       error
	calls     atomic.Int32
}

func (resolver *routingNameResolver) LookupIP(context.Context, string) ([]netip.Addr, error) {
	resolver.calls.Add(1)
	return append([]netip.Addr(nil), resolver.addresses...), resolver.err
}

func TestDomainRules_preserve_PPanel_semantics(t *testing.T) {
	// Given
	snapshot, err := Compile(Config{
		Block: []string{"", "keyword:ads", "suffix:blocked.example", "domain:legacy.example", "regex:^evil\\.example$", "regexp:^legacy-regex\\.example$", "full:exact.example", "full:exact.example"},
		Rules: []model.RouteRule{{Action: "direct", Match: []string{"suffix:edge.example"}}},
	})
	if err != nil {
		t.Fatalf("compile route snapshot: %v", err)
	}

	// When / Then
	for _, test := range []struct {
		domain string
		want   Target
	}{
		{"cdn.ads.example", Block},
		{"api.blocked.example", Block},
		{"api.legacy.example", Block},
		{"evil.example", Block},
		{"legacy-regex.example", Block},
		{"exact.example", Block},
		{"api.edge.example", Direct},
		{"unmatched.example", Direct},
	} {
		t.Run(test.domain, func(t *testing.T) {
			got := snapshot.Route(Request{Domain: test.domain, Network: UDP, Port: 443})
			if got.Target != test.want {
				t.Fatalf("target = %q, want %q", got.Target, test.want)
			}
		})
	}
}

func TestRouter_doesNotSelectMissingDNSOutbound(t *testing.T) {
	// Given
	snapshot, err := Compile(Config{})
	if err != nil {
		t.Fatalf("compile route snapshot: %v", err)
	}
	router := NewRouter(snapshot)

	// When
	decision := router.Route(context.Background(), Request{Domain: "example.com", Network: UDP, Port: 53})

	// Then
	if decision.Target != Direct {
		t.Fatalf("target = %q, want direct fallback", decision.Target)
	}
}

func TestRouter_matchesPrivateGeoIPAndCIDR(t *testing.T) {
	snapshot, err := Compile(Config{
		Block: []string{"geoip:private"},
		Rules: []model.RouteRule{{
			Action: "direct", Match: []string{"cidr:8.8.8.0/24"},
		}},
	})
	if err != nil {
		t.Fatalf("compile route snapshot: %v", err)
	}
	if got := snapshot.Route(Request{Domain: "192.168.1.2", Network: TCP, Port: 443}).Target; got != Block {
		t.Fatalf("private target = %q, want block", got)
	}
	if got := snapshot.Route(Request{Domain: "8.8.8.8", Network: TCP, Port: 443}).Target; got != Direct {
		t.Fatalf("CIDR target = %q, want edge", got)
	}
}

func TestRouter_matchesResolvedAddressesAgainstGeoIPAndCIDR(t *testing.T) {
	resolver := &routingNameResolver{addresses: []netip.Addr{
		netip.MustParseAddr("2001:db8::10"),
		netip.MustParseAddr("192.168.1.10"),
	}}
	router := NewRouter(MustCompile(Config{
		Block: []string{"geoip:private"},
		Rules: []model.RouteRule{{
			Action: "direct", Match: []string{"suffix:example.test"},
		}},
	}))

	decision := router.Route(WithNameResolver(context.Background(), resolver), Request{
		Domain: "api.example.test", Network: TCP, Port: 443,
	})

	if decision.Target != Block {
		t.Fatalf("target = %q, want block from resolved private address", decision.Target)
	}
	if !decision.Resolved || len(decision.Addresses) != 2 {
		t.Fatalf("decision = %#v, want both resolved addresses", decision)
	}
	if calls := resolver.calls.Load(); calls != 1 {
		t.Fatalf("resolver calls = %d, want 1", calls)
	}
}

func TestRouter_skipsResolutionWhenDomainMatchCannotBeBeaten(t *testing.T) {
	resolver := &routingNameResolver{addresses: []netip.Addr{netip.MustParseAddr("192.168.1.10")}}
	router := NewRouter(MustCompile(Config{
		Block: []string{"suffix:example.test"},
		Rules: []model.RouteRule{{
			Action: "direct", Match: []string{"geoip:private"},
		}},
	}))

	decision := router.Route(WithNameResolver(context.Background(), resolver), Request{
		Domain: "api.example.test", Network: TCP, Port: 443,
	})

	if decision.Target != Block {
		t.Fatalf("target = %q, want block", decision.Target)
	}
	if decision.Resolved || resolver.calls.Load() != 0 {
		t.Fatalf("unnecessary DNS resolution: decision=%#v calls=%d", decision, resolver.calls.Load())
	}
}

func TestRouter_resolvedIPRuleCanBeatLaterDomainRule(t *testing.T) {
	resolver := &routingNameResolver{addresses: []netip.Addr{netip.MustParseAddr("10.1.2.3")}}
	router := NewRouter(MustCompile(Config{
		Block: []string{"cidr:10.0.0.0/8"},
		Rules: []model.RouteRule{{
			Action: "direct", Match: []string{"suffix:example.test"},
		}},
	}))

	decision := router.Route(WithNameResolver(context.Background(), resolver), Request{
		Domain: "api.example.test", Network: TCP, Port: 443,
	})

	if decision.Target != Block || decision.RuleIndex != 0 || decision.Match != MatchCIDR {
		t.Fatalf("decision = %#v, want first CIDR rule", decision)
	}
}

func TestRouter_DNSFailureFallsBackToDomainOrDirect(t *testing.T) {
	wantErr := errors.New("DNS unavailable")
	for _, test := range []struct {
		name  string
		rules []string
		want  Target
		match MatchKind
	}{
		{name: "domain", rules: []string{"suffix:example.test"}, want: Direct, match: MatchDomain},
		{name: "direct", want: Direct, match: MatchDefault},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolver := &routingNameResolver{err: wantErr}
			router := NewRouter(MustCompile(Config{
				Block: []string{"geoip:private"},
				Rules: []model.RouteRule{{Action: "direct", Match: test.rules}},
			}))
			decision := router.Route(WithNameResolver(context.Background(), resolver), Request{
				Domain: "api.example.test", Network: TCP, Port: 443,
			})
			if decision.Target != test.want || decision.Match != test.match || !errors.Is(decision.ResolveError, wantErr) {
				t.Fatalf("decision = %#v, want target=%q match=%q and DNS error", decision, test.want, test.match)
			}
		})
	}
}

func TestCompile_rejects_invalid_regex_without_changing_active_snapshot(t *testing.T) {
	// Given
	router := NewRouter(MustCompile(Config{}))
	before := router.Snapshot().Hash()

	// When
	err := router.Replace(Config{Block: []string{"regex:("}})

	// Then
	if err == nil {
		t.Fatal("expected invalid regex error")
	}
	if got := router.Snapshot().Hash(); got != before {
		t.Fatalf("active snapshot hash = %q, want %q", got, before)
	}
}

func TestRouter_Replace_publishes_only_complete_snapshot_generations(t *testing.T) {
	// Given
	const (
		readerCount      = 16
		readerReadCount  = 64
		replacementCount = 32
		oldTarget        = Direct
		newTarget        = Block
	)
	oldConfig := Config{
		Block: []string{"suffix:old-blocked.example"},
		Rules: []model.RouteRule{{
			Action: string(oldTarget),
			Match:  []string{"suffix:old-custom.example"},
		}},
	}
	newConfig := Config{
		Block: []string{"suffix:new-blocked.example"},
		Rules: []model.RouteRule{{
			Action: string(newTarget),
			Match:  []string{"suffix:new-custom.example"},
		}},
	}
	router := NewRouter(MustCompile(oldConfig))
	isCompleteGeneration := func(snapshot *Snapshot) bool {
		if snapshot == nil {
			return false
		}
		oldBlocked := snapshot.Route(Request{Domain: "api.old-blocked.example", Network: TCP, Port: 443}).Target
		oldCustom := snapshot.Route(Request{Domain: "api.old-custom.example", Network: TCP, Port: 443}).Target
		newBlocked := snapshot.Route(Request{Domain: "api.new-blocked.example", Network: TCP, Port: 443}).Target
		newCustom := snapshot.Route(Request{Domain: "api.new-custom.example", Network: TCP, Port: 443}).Target
		return oldBlocked == Block && oldCustom == oldTarget && newBlocked == Direct && newCustom == Direct ||
			oldBlocked == Direct && oldCustom == Direct && newBlocked == Block && newCustom == newTarget
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ready := make(chan struct{}, readerCount)
	start := make(chan struct{})
	readerResults := make(chan string, readerCount)
	writerReady := make(chan struct{}, 1)
	writerResult := make(chan error, 1)
	for range readerCount {
		go func() {
			ready <- struct{}{}
			select {
			case <-start:
			case <-ctx.Done():
				readerResults <- "reader did not receive start signal"
				return
			}
			for range readerReadCount {
				if !isCompleteGeneration(router.Snapshot()) {
					readerResults <- "reader observed a mixed route snapshot"
					return
				}
			}
			readerResults <- ""
		}()
	}
	for range readerCount {
		select {
		case <-ready:
		case <-ctx.Done():
			t.Fatalf("wait for reader readiness: %v", ctx.Err())
		}
	}

	// When
	go func() {
		writerReady <- struct{}{}
		select {
		case <-start:
		case <-ctx.Done():
			writerResult <- ctx.Err()
			return
		}
		for index := range replacementCount {
			config := oldConfig
			if index%2 == 0 {
				config = newConfig
			}
			if err := router.Replace(config); err != nil {
				writerResult <- err
				return
			}
		}
		writerResult <- nil
	}()
	select {
	case <-writerReady:
	case <-ctx.Done():
		t.Fatalf("wait for replacement readiness: %v", ctx.Err())
	}
	close(start)

	// Then
	for range readerCount {
		select {
		case problem := <-readerResults:
			if problem != "" {
				t.Error(problem)
			}
		case <-ctx.Done():
			t.Fatalf("wait for snapshot readers: %v", ctx.Err())
		}
	}
	select {
	case err := <-writerResult:
		if err != nil {
			t.Fatalf("replace route snapshot: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("wait for route replacement: %v", ctx.Err())
	}
}
