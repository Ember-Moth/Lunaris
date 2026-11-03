// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors
// Adapted from Polaris 56d52fb44958ef3cc2a7fb841cd240f8206234b2.
package route

// Tie-break contract tests (semantic contract item 3 in
// docs/route-index-redesign.md): when one rule matches through several
// dimensions, the MatchKind reports the highest-rank dimension; across rules
// the earliest rule always wins regardless of rank.

import (
	"net/netip"
	"testing"

	"github.com/Ember-Moth/Lunaris/internal/model"
)

func TestMatchKindTieBreaks(t *testing.T) {
	catalog := writeDiffFixture(t)
	for _, test := range []struct {
		name    string
		block   []string
		domain  string
		address string
		want    MatchKind
	}{
		{
			name:   "ordinary full beats geosite on the same rule",
			block:  []string{"full:fx-full-a.example", "geosite:site-alpha"},
			domain: "fx-full-a.example",
			want:   MatchDomain,
		},
		{
			name:   "geosite beats ordinary keyword on the same rule",
			block:  []string{"geosite:site-alpha", "keyword:full-a"},
			domain: "fx-full-a.example",
			want:   MatchGeoSite,
		},
		{
			name:   "geosite suffix beats ordinary keyword on the same rule",
			block:  []string{"keyword:suffix-b", "geosite:site-beta"},
			domain: "api.fx-suffix-b.test",
			want:   MatchGeoSite,
		},
		{
			name:   "domain match beats CIDR on the same rule",
			block:  []string{"full:10.0.0.1", "cidr:10.0.0.0/8"},
			domain: "10.0.0.1",
			want:   MatchDomain,
		},
		{
			name:    "CIDR beats GeoIP on the same rule",
			block:   []string{"cidr:198.51.100.0/25", "geoip:geo-alpha"},
			address: "198.51.100.7",
			want:    MatchCIDR,
		},
		{
			name:    "geosite domain beats GeoIP on the same rule",
			block:   []string{"geosite:site-alpha", "geoip:geo-alpha"},
			domain:  "fx-full-a.example",
			address: "198.51.100.7",
			want:    MatchGeoSite,
		},
		{
			name:   "earlier geosite rule beats later ordinary full",
			block:  []string{"geosite:site-beta"},
			domain: "fx-full-b.example",
			want:   MatchGeoSite,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := MustCompile(Config{GeoData: catalog, Block: test.block})
			request := Request{Domain: test.domain, Network: TCP, Port: 443}
			if test.address != "" {
				request.Address = netip.MustParseAddr(test.address)
			}
			decision := snapshot.Route(request)
			if decision.Match != test.want {
				t.Fatalf("match kind = %q, want %q (decision %+v)", decision.Match, test.want, decision)
			}
		})
	}
}

func TestEarlierRuleWinsAcrossDimensions(t *testing.T) {
	catalog := writeDiffFixture(t)
	snapshot := MustCompile(Config{GeoData: catalog,
		Block: []string{"geosite:site-alpha"},
		Rules: []model.RouteRule{{
			Action: "direct",
			Match:  []string{"full:fx-full-a.example"},
		}},
	})
	decision := snapshot.Route(Request{Domain: "fx-full-a.example", Network: TCP, Port: 443})
	if decision.Target != Block || decision.Match != MatchGeoSite {
		t.Fatalf("decision = %+v, want block via geosite (rule 0)", decision)
	}
}

// TestSnapshotHashIsStructureIndependent pins contract item 8: the hash derives
// from rule identities, not from the index structures built on top of them.
func TestSnapshotHashIsStructureIndependent(t *testing.T) {
	catalog := writeDiffFixture(t)
	config := Config{GeoData: catalog,
		Block: []string{"keyword:ads", "suffix:blocked.example", "cidr:10.0.0.0/8"},
		Rules: []model.RouteRule{{
			Action: "direct",
			Match:  []string{"full:exact.example", "geoip:private", "regex:^evil\\."},
		}},
	}
	first := MustCompile(config)
	second := MustCompile(config)
	if first.Hash() != second.Hash() {
		t.Fatalf("hash mismatch across compiles: %q vs %q", first.Hash(), second.Hash())
	}
	changed := config
	changed.Block = []string{"keyword:trackers", "suffix:blocked.example", "cidr:10.0.0.0/8"}
	if first.Hash() == MustCompile(changed).Hash() {
		t.Fatal("hash did not change after changing a selector")
	}
}
