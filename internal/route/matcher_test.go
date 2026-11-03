// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors
// Adapted from Polaris 56d52fb44958ef3cc2a7fb841cd240f8206234b2.
package route

import (
	"math/rand"
	"net/netip"
	"strings"
	"testing"

	"github.com/Ember-Moth/Lunaris/internal/model"
)

func TestPrefixSetMatchesNaiveReference(t *testing.T) {
	random := rand.New(rand.NewSource(7))
	prefixes := make([]netip.Prefix, 0, 512)
	for range 256 {
		address := netip.AddrFrom4([4]byte{
			byte(random.Uint32()), byte(random.Uint32()), byte(random.Uint32()), byte(random.Uint32()),
		})
		prefixes = append(prefixes, netip.PrefixFrom(address, random.Intn(33)).Masked())
	}
	for range 256 {
		var raw [16]byte
		_, _ = random.Read(raw[:])
		prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom16(raw), random.Intn(129)).Masked())
	}
	set := newPrefixSet(prefixes)
	for range 4096 {
		var address netip.Addr
		if random.Intn(2) == 0 {
			address = netip.AddrFrom4([4]byte{
				byte(random.Uint32()), byte(random.Uint32()), byte(random.Uint32()), byte(random.Uint32()),
			})
		} else {
			var raw [16]byte
			_, _ = random.Read(raw[:])
			address = netip.AddrFrom16(raw)
		}
		want := false
		for _, prefix := range prefixes {
			if prefix.Contains(address) {
				want = true
				break
			}
		}
		if got := set.Contains(address); got != want {
			t.Fatalf("Contains(%s) = %v, want %v", address, got, want)
		}
	}
}

func TestKeywordMatcherMatchesContainsReference(t *testing.T) {
	keywords := []string{"he", "she", "his", "hers", "blocked", "广告", "example-cdn"}
	matcher := newKeywordMatcher(keywords)
	for _, value := range []string{
		"ushers.example", "history.example", "clean.example", "api.blocked.test",
		"广告.example", "static.example-cdn.test", "short.h.test",
	} {
		want := false
		for _, keyword := range keywords {
			if strings.Contains(value, keyword) {
				want = true
				break
			}
		}
		if got := matcher.match(value); got != want {
			t.Fatalf("match(%q) = %v, want %v", value, got, want)
		}
	}
}

func TestRouteIndexesPreserveFirstMatchPriority(t *testing.T) {
	snapshot := MustCompile(Config{
		Block: []string{"cidr:10.1.0.0/16", "suffix:first.example"},
		Rules: []model.RouteRule{
			{Action: "direct", Match: []string{"cidr:10.0.0.0/8", "suffix:example"}},
			{Action: "direct", Match: []string{"full:api.first.example"}},
		},
	})
	for _, test := range []struct {
		destination string
		want        Target
	}{
		{destination: "api.first.example", want: Block},
		{destination: "10.1.2.3", want: Block},
		{destination: "10.2.3.4", want: Direct},
		{destination: "api.example", want: Direct},
	} {
		if got := snapshot.Route(Request{Domain: test.destination}).Target; got != test.want {
			t.Fatalf("Route(%q) = %q, want %q", test.destination, got, test.want)
		}
	}
}

func TestRegexMatchingIsDomainCaseInsensitive(t *testing.T) {
	snapshot := MustCompile(Config{Block: []string{`regex:^API\.EXAMPLE$`}})
	if decision := snapshot.Route(Request{Domain: "api.example"}); decision.Target != Block {
		t.Fatalf("decision = %#v, want case-insensitive regex block", decision)
	}
}

func TestCanonicalSelectorOrderProducesStableHash(t *testing.T) {
	first := MustCompile(Config{Block: []string{"suffix:b.example", "full:a.example", "cidr:10.0.0.0/8"}})
	second := MustCompile(Config{Block: []string{"cidr:10.0.0.0/8", "full:a.example", "suffix:b.example"}})
	if first.Hash() != second.Hash() {
		t.Fatalf("equivalent selector hashes differ: %q != %q", first.Hash(), second.Hash())
	}
	left, err := parseGeoSiteCategory("test@cn@ads")
	if err != nil {
		t.Fatal(err)
	}
	right, err := parseGeoSiteCategory("TEST@ads@cn")
	if err != nil {
		t.Fatal(err)
	}
	if left.key != right.key {
		t.Fatalf("canonical geosite keys differ: %q != %q", left.key, right.key)
	}
}

func TestCompileStatsAndDecisionTrace(t *testing.T) {
	var traces []DecisionTrace
	snapshot := MustCompile(Config{
		Block: []string{"full:blocked.example", "suffix:example", "keyword:ads", "regex:^evil", "cidr:10.0.0.0/8"},
		Trace: func(trace DecisionTrace) { traces = append(traces, trace) },
	})
	decision := snapshot.Route(Request{Domain: "blocked.example", Network: TCP, Port: 443})
	if decision.Target != Block || len(traces) != 1 {
		t.Fatalf("decision/traces = %#v/%#v", decision, traces)
	}
	if traces[0].RuleIndex != 0 || traces[0].Match != MatchDomain || traces[0].Domain != "blocked.example" {
		t.Fatalf("trace = %#v", traces[0])
	}
	stats := snapshot.Stats()
	if stats.Rules != 1 || stats.DomainExact != 1 || stats.DomainSuffix != 1 || stats.KeywordNodes == 0 || stats.RegexRules != 1 || stats.CIDRNodes == 0 || stats.EstimatedBytes == 0 || stats.CompileDuration <= 0 {
		t.Fatalf("stats = %#v", stats)
	}
}
