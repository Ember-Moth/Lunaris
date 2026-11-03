// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors
// Adapted from Polaris 56d52fb44958ef3cc2a7fb841cd240f8206234b2.
package route

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// ruleSelectors keeps ordinary selectors local to one rule while referencing
// configuration-owned immutable GeoData matchers. This prevents every inbound runtime
// from expanding the same large geosite/geoip category into another heap copy.
type ruleSelectors struct {
	domains          []*domainSet
	domainKind       []MatchKind
	prefixes         []*prefixSet
	prefixKind       []MatchKind
	ordinaryDomain   *domainSet
	ordinaryPrefixes []netip.Prefix
	identities       []string
}

func compileRuleSelectors(values []string, catalog *Catalog) (ruleSelectors, error) {
	var compiled ruleSelectors
	domains := make([]Selector, 0, len(values))
	prefixes := make([]netip.Prefix, 0)
	domainSeen := make(map[string]struct{})
	prefixSeen := make(map[netip.Prefix]struct{})
	geoSiteSeen := make(map[string]struct{})
	geoIPSeen := make(map[string]struct{})
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		lower := strings.ToLower(value)
		if categoryValue, found := strings.CutPrefix(lower, "geosite:"); found {
			category, err := parseGeoSiteCategory(categoryValue)
			if err != nil {
				return ruleSelectors{}, err
			}
			if _, exists := geoSiteSeen[category.key]; exists {
				continue
			}
			set, err := catalog.loadSite(categoryValue)
			if err != nil {
				return ruleSelectors{}, err
			}
			geoSiteSeen[category.key] = struct{}{}
			if set != nil {
				compiled.domains = append(compiled.domains, set)
				compiled.domainKind = append(compiled.domainKind, MatchGeoSite)
			}
			identity := "geosite:" + category.key
			if set != nil {
				identity += ":" + set.hash
			}
			compiled.identities = append(compiled.identities, identity)
			continue
		}
		if categoryValue, found := strings.CutPrefix(lower, "geoip:"); found {
			category, err := normalizeGeoCategory(categoryValue)
			if err != nil {
				return ruleSelectors{}, err
			}
			if _, exists := geoIPSeen[category]; exists {
				continue
			}
			var set *prefixSet
			if category == "PRIVATE" {
				set = builtInPrivatePrefixSet()
			} else {
				set, err = catalog.loadIP(category)
				if err != nil {
					return ruleSelectors{}, err
				}
			}
			geoIPSeen[category] = struct{}{}
			if set != nil {
				compiled.prefixes = append(compiled.prefixes, set)
				compiled.prefixKind = append(compiled.prefixKind, MatchGeoIP)
			}
			identity := "geoip:" + category
			if set != nil {
				identity += ":" + set.hash
			}
			compiled.identities = append(compiled.identities, identity)
			continue
		}
		if prefixValue, found := cutIPPrefix(value); found {
			prefix, err := parseIPPrefix(prefixValue)
			if err != nil {
				return ruleSelectors{}, fmt.Errorf("route: invalid IP prefix %q", value)
			}
			if _, exists := prefixSeen[prefix]; !exists {
				prefixSeen[prefix] = struct{}{}
				prefixes = append(prefixes, prefix)
				compiled.identities = append(compiled.identities, "ip:"+prefix.String())
			}
			continue
		}
		loaded, err := ParseSelectors([]string{value})
		if err != nil {
			return ruleSelectors{}, err
		}
		for _, selector := range loaded {
			key := selector.Key()
			if _, exists := domainSeen[key]; exists {
				continue
			}
			domainSeen[key] = struct{}{}
			domains = append(domains, selector)
			compiled.identities = append(compiled.identities, "domain:"+key)
		}
	}
	if set := newDomainSet(domains); set != nil {
		compiled.ordinaryDomain = set
		compiled.domains = append(compiled.domains, set)
		compiled.domainKind = append(compiled.domainKind, MatchDomain)
	}
	if set := newPrefixSet(prefixes); set != nil {
		compiled.ordinaryPrefixes = canonicalIPPrefixes(prefixes)
		compiled.prefixes = append(compiled.prefixes, set)
		compiled.prefixKind = append(compiled.prefixKind, MatchCIDR)
	}
	slices.Sort(compiled.identities)
	compiled.identities = slices.Compact(compiled.identities)
	return compiled, nil
}

func (selectors ruleSelectors) empty() bool {
	return len(selectors.domains) == 0 && len(selectors.prefixes) == 0
}

func (selectors ruleSelectors) matchDomainNormalized(domain string) MatchKind {
	for index, set := range selectors.domains {
		if set.MatchNormalized(domain) {
			return selectors.domainKind[index]
		}
	}
	return ""
}

// regexDomainRank reports whether any domain set carries regex selectors and,
// if so, the best rank they can produce: GeoSite regexes rank 1, ordinary
// regexes rank 2. Full/suffix selectors live in the snapshot-wide merged index
// and keywords in the merged automaton, so only regexes keep a rule on the
// per-rule slow scan.
func (selectors ruleSelectors) regexDomainRank() (uint32, bool) {
	rank := uint32(0)
	found := false
	for index, set := range selectors.domains {
		if set == nil || len(set.regex) == 0 {
			continue
		}
		candidate := uint32(2)
		if selectors.domainKind[index] == MatchGeoSite {
			candidate = 1
		}
		if !found || candidate < rank {
			rank = candidate
		}
		found = true
	}
	return rank, found
}

func parseIPPrefix(value string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Masked(), nil
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	address = address.Unmap()
	return netip.PrefixFrom(address, address.BitLen()), nil
}

func cutIPPrefix(value string) (string, bool) {
	lower := strings.ToLower(value)
	for _, prefix := range []string{"ip:", "cidr:"} {
		if strings.HasPrefix(lower, prefix) {
			return strings.TrimSpace(value[len(prefix):]), true
		}
	}
	if strings.Contains(value, "/") {
		return value, true
	}
	return "", false
}
