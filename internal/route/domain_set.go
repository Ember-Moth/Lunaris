// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors
// Adapted from Polaris 56d52fb44958ef3cc2a7fb841cd240f8206234b2.
package route

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

type domainSet struct {
	full     domainTable
	suffix   domainTable
	keywords keywordMatcher
	regex    []*regexp.Regexp
	hash     string
	source   geoDataVersion
}

func newDomainSet(selectors []Selector) *domainSet {
	selectors = canonicalDomainSelectors(selectors)
	if len(selectors) == 0 {
		return nil
	}
	full := make([]string, 0, len(selectors))
	suffixes := make([]string, 0, len(selectors))
	keywords := make([]string, 0, len(selectors))
	regexes := make([]*regexp.Regexp, 0, len(selectors))
	for _, selector := range selectors {
		switch selector.kind {
		case selectorFull:
			full = append(full, selector.value)
		case selectorSuffix:
			suffixes = append(suffixes, selector.value)
		case selectorKeyword:
			keywords = append(keywords, selector.value)
		case selectorRegex:
			regexes = append(regexes, selector.regex)
		}
	}
	return &domainSet{
		full: newDomainTable(full), suffix: newDomainTable(suffixes),
		keywords: newKeywordMatcher(keywords), regex: slices.Clip(regexes),
		hash: hashDomainSelectors(selectors),
	}
}

func canonicalDomainSelectors(selectors []Selector) []Selector {
	canonical := append([]Selector(nil), selectors...)
	slices.SortFunc(canonical, func(left, right Selector) int {
		if left.kind < right.kind {
			return -1
		}
		if left.kind > right.kind {
			return 1
		}
		return strings.Compare(left.value, right.value)
	})
	return slices.CompactFunc(canonical, func(left, right Selector) bool {
		return left.kind == right.kind && left.value == right.value
	})
}

func hashDomainSelectors(selectors []Selector) string {
	hash := sha256.New()
	for _, selector := range selectors {
		_, _ = hash.Write([]byte(strconv.Itoa(int(selector.kind))))
		_, _ = hash.Write([]byte{':'})
		_, _ = hash.Write([]byte(selector.value))
		_, _ = hash.Write([]byte{'\n'})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func (set *domainSet) Match(domain string) bool {
	return set.MatchNormalized(normalizeDomain(domain))
}

// MatchNormalized matches a hostname that has already been normalized by the
// routing or DNS entry point.
func (set *domainSet) MatchNormalized(domain string) bool {
	if set == nil || domain == "" {
		return false
	}
	if set.full.contains(domain) {
		return true
	}
	for candidate := domain; candidate != ""; {
		if set.suffix.contains(candidate) {
			return true
		}
		_, next, found := strings.Cut(candidate, ".")
		if !found {
			break
		}
		candidate = next
	}
	if set.keywords.match(domain) {
		return true
	}
	for _, expression := range set.regex {
		if expression.MatchString(domain) {
			return true
		}
	}
	return false
}

func (set *domainSet) estimatedBytes() uint64 {
	if set == nil {
		return 0
	}
	size := set.full.estimatedBytes() + set.suffix.estimatedBytes() + set.keywords.estimatedBytes()
	for _, expression := range set.regex {
		size += uint64(len(expression.String()) + 64)
	}
	return size
}
