// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors
// Adapted from Polaris 56d52fb44958ef3cc2a7fb841cd240f8206234b2.
// Package route compiles PPanel domain routing rules into immutable snapshots.
package route

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

type selectorKind uint8

const (
	selectorFull selectorKind = iota
	selectorSuffix
	selectorKeyword
	selectorRegex
)

// Selector is one immutable, parsed PPanel domain selector.
type Selector struct {
	kind  selectorKind
	value string
	regex *regexp.Regexp
}

// DomainMatcher is an immutable domain predicate. GeoData-backed matchers keep
// their decoded category shared instead of expanding it into every consumer.
type DomainMatcher interface {
	Match(string) bool
	MatchNormalized(string) bool
	Key() string
}

type geoSiteMatcher struct {
	key string
	set *domainSet
}

func (matcher geoSiteMatcher) Match(domain string) bool { return matcher.set.Match(domain) }
func (matcher geoSiteMatcher) MatchNormalized(domain string) bool {
	return matcher.set.MatchNormalized(domain)
}

func (matcher geoSiteMatcher) Key() string {
	return "geosite:" + matcher.key + ":" + matcher.set.hash
}

// CompileDomainMatchers compiles ordinary and geosite selectors while sharing
// configuration-owned category matchers. ParseSelectors remains available for callers
// that explicitly need a flattened compatibility representation.
func CompileDomainMatchers(values []string, catalogs ...*Catalog) ([]DomainMatcher, error) {
	var catalog *Catalog
	if len(catalogs) > 0 {
		catalog = catalogs[0]
	}
	matchers := make([]DomainMatcher, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		if categoryValue, found := strings.CutPrefix(strings.ToLower(value), "geosite:"); found {
			category, err := parseGeoSiteCategory(categoryValue)
			if err != nil {
				return nil, err
			}
			key := "geosite:" + category.key
			if _, exists := seen[key]; exists {
				continue
			}
			set, err := catalog.loadSite(categoryValue)
			if err != nil {
				return nil, err
			}
			seen[key] = struct{}{}
			if set != nil {
				matchers = append(matchers, geoSiteMatcher{key: category.key, set: set})
			}
			continue
		}
		if _, candidate, found := strings.Cut(value, ":"); found && strings.TrimSpace(candidate) == "" {
			continue
		}
		selector, _, err := parseSelector(value)
		if err != nil {
			return nil, err
		}
		key := selector.Key()
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		matchers = append(matchers, selector)
	}
	return matchers, nil
}

// ParseSelectors parses PPanel full, suffix, keyword, and regex selector strings.
func ParseSelectors(values []string) ([]Selector, error) {
	selectors := make([]Selector, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		if category, found := strings.CutPrefix(strings.ToLower(strings.TrimSpace(raw)), "geosite:"); found {
			expanded, err := (*Catalog)(nil).siteSelectors(category)
			if err != nil {
				return nil, err
			}
			for _, selector := range expanded {
				key := selector.Key()
				if _, exists := seen[key]; exists {
					continue
				}
				seen[key] = struct{}{}
				selectors = append(selectors, selector)
			}
			continue
		}
		if _, value, found := strings.Cut(raw, ":"); found && strings.TrimSpace(value) == "" {
			continue
		}
		selector, key, err := parseSelector(raw)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		selectors = append(selectors, selector)
	}
	return selectors, nil
}

func parseSelector(raw string) (Selector, string, error) {
	if len(raw) > 4096 {
		return Selector{}, "", fmt.Errorf("route: selector exceeds 4096 bytes")
	}
	value := strings.TrimSpace(raw)
	if value == "" {
		return Selector{}, "", errors.New("route: empty domain selector")
	}
	kind := selectorFull
	if prefix, candidate, found := strings.Cut(value, ":"); found {
		value = strings.TrimSpace(candidate)
		switch strings.ToLower(strings.TrimSpace(prefix)) {
		case "full":
			kind = selectorFull
		case "suffix", "domain":
			kind = selectorSuffix
		case "keyword", "plain":
			kind = selectorKeyword
		case "regex", "regexp":
			kind = selectorRegex
		default:
			kind = selectorFull
		}
	}
	if value == "" {
		return Selector{}, "", fmt.Errorf("route: empty domain selector %q", raw)
	}
	if kind == selectorRegex {
		compiled, err := regexp.Compile("(?i:" + value + ")")
		if err != nil {
			return Selector{}, "", fmt.Errorf("route: compile domain regex: %w", err)
		}
		return Selector{kind: kind, value: value, regex: compiled}, "regex:" + value, nil
	}
	value = normalizeDomain(value)
	return Selector{kind: kind, value: value}, fmt.Sprintf("%d:%s", kind, value), nil
}

// Match reports whether the normalized hostname matches the selector.
func (selector Selector) Match(domain string) bool {
	return selector.MatchNormalized(normalizeDomain(domain))
}

// MatchNormalized matches a hostname normalized by normalizeDomain.
func (selector Selector) MatchNormalized(domain string) bool {
	switch selector.kind {
	case selectorFull:
		return domain == selector.value
	case selectorSuffix:
		return domain == selector.value || strings.HasSuffix(domain, "."+selector.value)
	case selectorKeyword:
		return strings.Contains(domain, selector.value)
	case selectorRegex:
		return selector.regex.MatchString(domain)
	default:
		return false
	}
}

// Key returns the normalized immutable selector identity.
func (selector Selector) Key() string {
	return fmt.Sprintf("%d:%s", selector.kind, selector.value)
}

func normalizeDomain(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}
