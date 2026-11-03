// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors
// Adapted from Polaris 56d52fb44958ef3cc2a7fb841cd240f8206234b2.
package route

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
)

// Network identifies a request transport.
type Network string

// Networks a route request can carry.
const (
	TCP Network = "tcp"
	UDP Network = "udp"
)

// DestinationKind lets protocol adapters pass the address type they already
// decoded, avoiding a failed netip parse allocation for every domain request.
type DestinationKind uint8

// Destination kinds a route request can carry.
const (
	DestinationAuto DestinationKind = iota
	DestinationDomain
	DestinationIP
)

// Request is the product-owned routing input.
type Request struct {
	Domain  string
	Address netip.Addr
	Kind    DestinationKind
	Network Network
	Port    uint16
}

// MatchKind identifies the matcher that selected a route.
type MatchKind string

// Match kinds a routing decision records.
const (
	MatchDefault MatchKind = "default"
	MatchDomain  MatchKind = "domain"
	MatchGeoSite MatchKind = "geosite"
	MatchCIDR    MatchKind = "cidr"
	MatchGeoIP   MatchKind = "geoip"
	MatchDNS     MatchKind = "dns"
)

// Decision records the selected route target and enough diagnostic context to
// explain it. Addresses are populated only when routing required DNS.
type Decision struct {
	Target       Target
	RuleIndex    int
	Match        MatchKind
	Resolved     bool
	DNSAttempted bool
	Addresses    []netip.Addr
	ResolveError error
}

// DecisionTrace is emitted only when Config.Trace is configured.
type DecisionTrace struct {
	Domain       string
	Network      Network
	Port         uint16
	Target       Target
	RuleIndex    int
	Match        MatchKind
	DNSAttempted bool
	AddressCount int
	ResolveError string
}

// CompileStats describes immutable matcher and index size for one snapshot.
type CompileStats struct {
	Rules, DomainExact, DomainSuffix, SlowDomainRules int
	CIDRNodes, GeoIPRules, GeoSiteCategories          int
	GeoIPCategories, DomainMatcherSets, PrefixSets    int
	KeywordNodes, RegexRules, PrefixNodes             int
	GeoDataAssets                                     int
	EstimatedBytes                                    uint64
	CompileDuration                                   time.Duration
}

// GeoDataFingerprint identifies one asset generation referenced by a snapshot.
type GeoDataFingerprint struct {
	Path     string
	Size     int64
	Modified time.Time
	ID       string
}

// Config is the validated application routing boundary.
type Config struct {
	Block   []string
	Rules   []model.RouteRule
	GeoData *Catalog
	Logger  *slog.Logger
	Trace   func(DecisionTrace)
	Targets []Target
	Final   Target
}

type rule struct {
	target    Target
	selectors ruleSelectors
}

// Snapshot is an immutable compiled route table.
type Snapshot struct {
	rules           []rule
	hash            string
	earliestIPRule  int
	domains         domainIndex
	keywords        keywordRuleIndex
	regexRules      []uint32 // packRule(index, minRegexRank), ascending
	ipIndex         *prefixRuleIndex
	geoIPRules      int
	geoDataVersions []geoDataVersion
	stats           CompileStats
	trace           func(DecisionTrace)
	final           Target
}

// Compile validates routing configuration without mutating an active router.
func Compile(config Config) (*Snapshot, error) {
	started := time.Now()
	targets := map[Target]bool{Direct: true, Block: true}
	for _, target := range config.Targets {
		if target == "" || target == DNS || targets[target] {
			return nil, fmt.Errorf("route: invalid or duplicate outbound target")
		}
		targets[target] = true
	}
	final := config.Final
	if final == "" {
		final = Direct
	}
	if !targets[final] {
		return nil, fmt.Errorf("route: final outbound is not configured")
	}
	block, err := compileRuleSelectors(config.Block, config.GeoData)
	if err != nil {
		return nil, err
	}
	rules := make([]rule, 0, len(config.Rules)+1)
	if !block.empty() {
		rules = append(rules, rule{target: Block, selectors: block})
	}
	for index, item := range config.Rules {
		target := Target(item.Action)
		if item.Action == "route" {
			target = Target(item.Outbound)
			if target == Direct || target == Block || !targets[target] {
				return nil, fmt.Errorf("route: rule %d references an unknown outbound", index)
			}
		} else if (target != Direct && target != Block) || item.Outbound != "" {
			return nil, fmt.Errorf("route: rule %d has unsupported action", index)
		}
		selectors, err := compileRuleSelectors(item.Match, config.GeoData)
		if err != nil {
			return nil, fmt.Errorf("route: rule %d: %w", index, err)
		}
		if selectors.empty() {
			continue
		}
		rules = append(rules, rule{target: target, selectors: selectors})
	}
	snapshot := compileSnapshot(rules)
	snapshot.final = final
	if final != Direct {
		sum := sha256.Sum256([]byte(snapshot.hash + "\x00" + string(final)))
		snapshot.hash = hex.EncodeToString(sum[:])
	}
	snapshot.stats.CompileDuration = time.Since(started)
	snapshot.trace = config.Trace
	return snapshot, nil
}

func compileSnapshot(rules []rule) *Snapshot {
	snapshot := &Snapshot{
		rules: rules, hash: snapshotHash(rules), earliestIPRule: len(rules),
		ipIndex: newPrefixRuleIndex(),
	}
	domains := newDomainIndexBuilder()
	keywords := keywordRuleBuilder{}
	domains.reserve(countDomainEntries(rules))
	geoDataVersions := make(map[string]geoDataVersion)
	for ruleIndex := range snapshot.rules {
		snapshot.indexRuleDomains(ruleIndex, domains, &keywords, geoDataVersions)
		snapshot.indexRulePrefixes(ruleIndex, geoDataVersions)
	}
	snapshot.domains = domains.build()
	snapshot.keywords = keywords.build()
	for _, version := range geoDataVersions {
		snapshot.geoDataVersions = append(snapshot.geoDataVersions, version)
	}
	slices.SortFunc(snapshot.geoDataVersions, func(left, right geoDataVersion) int {
		return strings.Compare(left.path, right.path)
	})
	snapshot.buildStats()
	return snapshot
}

// countDomainEntries sums full/suffix entries over distinct domain sets so the
// frozen table can reserve capacity once instead of growing by rehashing.
func countDomainEntries(rules []rule) int {
	count := 0
	seen := make(map[*domainSet]struct{})
	for ruleIndex := range rules {
		for _, set := range rules[ruleIndex].selectors.domains {
			if set == nil {
				continue
			}
			if _, exists := seen[set]; exists {
				continue
			}
			seen[set] = struct{}{}
			count += set.full.len() + set.suffix.len()
		}
	}
	return count
}

// indexRuleDomains merges one rule's domain selectors into the snapshot-wide
// table and automaton. Ranks preserve the diagnostic tie-breaks: ordinary
// full/suffix = 0, GeoSite = 1, ordinary keyword/regex = 2.
func (snapshot *Snapshot) indexRuleDomains(ruleIndex int, domains *domainIndexBuilder, keywords *keywordRuleBuilder,
	geoDataVersions map[string]geoDataVersion,
) {
	selectors := &snapshot.rules[ruleIndex].selectors
	for setIndex, set := range selectors.domains {
		if set == nil {
			continue
		}
		if set.source.path != "" {
			geoDataVersions[set.source.path] = set.source
		}
		fullSuffixRank := uint32(0)
		keywordRank := uint32(2)
		if selectors.domainKind[setIndex] == MatchGeoSite {
			fullSuffixRank = 1
			keywordRank = 1
		}
		set.full.each(func(value string) { domains.insert(value, false, ruleIndex, fullSuffixRank) })
		set.suffix.each(func(value string) { domains.insert(value, true, ruleIndex, fullSuffixRank) })
		for _, keyword := range set.keywords.list {
			keywords.insert(keyword, ruleIndex, keywordRank)
		}
	}
	if minRank, hasRegex := selectors.regexDomainRank(); hasRegex {
		snapshot.regexRules = append(snapshot.regexRules, packRule(ruleIndex, minRank))
	}
}

// indexRulePrefixes merges one rule's ordinary CIDR and GeoIP (including the
// built-in private ranges) into the shared priority trie, with rank preserving
// the CIDR-over-GeoIP same-rule tie-break.
func (snapshot *Snapshot) indexRulePrefixes(ruleIndex int, geoDataVersions map[string]geoDataVersion) {
	selectors := &snapshot.rules[ruleIndex].selectors
	for _, set := range selectors.prefixes {
		if set != nil && set.source.path != "" {
			geoDataVersions[set.source.path] = set.source
		}
	}
	for _, prefix := range selectors.ordinaryPrefixes {
		snapshot.ipIndex.insert(prefix, ruleIndex, 0)
		if ruleIndex < snapshot.earliestIPRule {
			snapshot.earliestIPRule = ruleIndex
		}
	}
	selectors.ordinaryPrefixes = nil
	hasGeoIP := false
	for setIndex, set := range selectors.prefixes {
		if set == nil || selectors.prefixKind[setIndex] != MatchGeoIP {
			continue
		}
		for _, prefix := range set.list {
			snapshot.ipIndex.insert(prefix, ruleIndex, 1)
		}
		hasGeoIP = true
	}
	if hasGeoIP {
		snapshot.geoIPRules++
		if ruleIndex < snapshot.earliestIPRule {
			snapshot.earliestIPRule = ruleIndex
		}
	}
}

func (snapshot *Snapshot) buildStats() {
	stats := CompileStats{
		Rules: len(snapshot.rules), DomainExact: snapshot.domains.exact,
		DomainSuffix: snapshot.domains.suffix, SlowDomainRules: len(snapshot.regexRules),
		GeoIPRules: snapshot.geoIPRules, GeoDataAssets: len(snapshot.geoDataVersions),
		KeywordNodes: len(snapshot.keywords.nodes),
	}
	if snapshot.ipIndex != nil && len(snapshot.ipIndex.nodes) > 2 {
		stats.CIDRNodes = len(snapshot.ipIndex.nodes)
	} else if snapshot.ipIndex != nil &&
		(snapshot.ipIndex.nodes[0].packed > 0 || snapshot.ipIndex.nodes[1].packed > 0) {
		stats.CIDRNodes = len(snapshot.ipIndex.nodes)
	}
	stats.EstimatedBytes += snapshot.ipIndex.estimatedBytes()
	stats.EstimatedBytes += snapshot.domains.estimatedBytes()
	stats.EstimatedBytes += snapshot.keywords.estimatedBytes()
	stats.EstimatedBytes += uint64(len(snapshot.regexRules)) * 4
	snapshot.addSetStats(&stats)
	snapshot.stats = stats
}

// addSetStats folds the shared, deduplicated domain and prefix matcher sets
// into the compile statistics.
func (snapshot *Snapshot) addSetStats(stats *CompileStats) {
	domains := make(map[*domainSet]struct{})
	prefixes := make(map[*prefixSet]struct{})
	for index := range snapshot.rules {
		for _, set := range snapshot.rules[index].selectors.domains {
			if set == nil {
				continue
			}
			if _, exists := domains[set]; exists {
				continue
			}
			domains[set] = struct{}{}
			stats.DomainMatcherSets++
			stats.EstimatedBytes += set.estimatedBytes()
			stats.RegexRules += len(set.regex)
			if set.source.path != "" && set.source.kind == geoDataSite {
				stats.GeoSiteCategories++
			}
		}
		for _, set := range snapshot.rules[index].selectors.prefixes {
			if set == nil {
				continue
			}
			if _, exists := prefixes[set]; exists {
				continue
			}
			prefixes[set] = struct{}{}
			stats.PrefixSets++
			stats.EstimatedBytes += set.estimatedBytes()
			stats.PrefixNodes += len(set.nodes)
			if set.source.path != "" && set.source.kind == geoDataIP {
				stats.GeoIPCategories++
			}
		}
	}
}

// Stats returns a value copy of snapshot compilation and matcher statistics.
func (snapshot *Snapshot) Stats() CompileStats { return snapshot.stats }

// GeoDataFingerprints returns value copies suitable for diagnostics.
func (snapshot *Snapshot) GeoDataFingerprints() []GeoDataFingerprint {
	result := make([]GeoDataFingerprint, 0, len(snapshot.geoDataVersions))
	for _, version := range snapshot.geoDataVersions {
		result = append(result, GeoDataFingerprint{ID: version.path, Size: version.size})
	}
	return result
}

// MustCompile is for trusted defaults and tests.
func MustCompile(config Config) *Snapshot {
	snapshot, err := Compile(config)
	if err != nil {
		panic(err)
	}
	return snapshot
}

// Hash identifies immutable compiled configuration without exposing secrets.
func (snapshot *Snapshot) Hash() string { return snapshot.hash }

// Route applies ordered rules, then the configured final target (default direct).
func (snapshot *Snapshot) Route(request Request) Decision {
	domain := normalizeDomain(request.Domain)
	best, kind := snapshot.matchDomain(domain, len(snapshot.rules))
	if address := requestAddress(request, domain); address.IsValid() {
		best, kind = snapshot.matchAddress(address, best, kind)
	}
	return snapshot.finish(request, snapshot.decision(best, kind))
}

func requestAddress(request Request, normalizedDomain string) netip.Addr {
	if request.Address.IsValid() {
		return request.Address.Unmap()
	}
	if request.Kind == DestinationDomain {
		return netip.Addr{}
	}
	address, _ := netip.ParseAddr(normalizedDomain)
	return address.Unmap()
}

func (snapshot *Snapshot) finish(request Request, decision Decision) Decision {
	if snapshot.trace != nil {
		trace := DecisionTrace{
			Domain: normalizeDomain(request.Domain), Network: request.Network, Port: request.Port,
			Target: decision.Target, RuleIndex: decision.RuleIndex, Match: decision.Match,
			DNSAttempted: decision.DNSAttempted, AddressCount: len(decision.Addresses),
		}
		if decision.ResolveError != nil {
			trace.ResolveError = decision.ResolveError.Error()
		}
		snapshot.trace(trace)
	}
	return decision
}

// matchDomain resolves the earliest matching rule through the packed pipeline:
// merged full/suffix table, merged keyword automaton, then the regex-only slow
// scan. Ranks inside the packed values preserve the MatchKind tie-breaks, so
// the result is identical to the legacy per-rule scan.
func (snapshot *Snapshot) matchDomain(domain string, limit int) (int, MatchKind) {
	limitPacked := packRule(limit, 0)
	best := snapshot.domains.matchPacked(domain, limitPacked)
	if best == 0 {
		best = limitPacked
	}
	if best > packRule(0, 1) {
		// Nothing a keyword or regex can produce beats rule 0 through GeoSite,
		// so the automaton pass is skipped for the common block-first hit.
		best = snapshot.keywords.matchPacked(domain, best)
	}
	for _, encoded := range snapshot.regexRules {
		if encoded >= best {
			break
		}
		index := asInt(encoded>>2) - 1
		if matched := snapshot.rules[index].selectors.matchDomainNormalized(domain); matched != "" {
			rank := uint32(2)
			if matched == MatchGeoSite {
				rank = 1
			}
			if actual := packRule(index, rank); actual < best {
				best = actual
			}
		}
	}
	if best == limitPacked {
		return limit, MatchDefault
	}
	return asInt(best>>2) - 1, domainKindOfRank(best & 3)
}

func (snapshot *Snapshot) matchAddress(address netip.Addr, limit int, fallback MatchKind) (int, MatchKind) {
	packed := snapshot.ipIndex.lookup(address, limit)
	if packed == 0 {
		return limit, fallback
	}
	if packed&3 != 0 {
		return asInt(packed>>2) - 1, MatchGeoIP
	}
	return asInt(packed>>2) - 1, MatchCIDR
}

func (snapshot *Snapshot) decision(index int, kind MatchKind) Decision {
	if index >= 0 && index < len(snapshot.rules) {
		return Decision{Target: snapshot.rules[index].target, RuleIndex: index, Match: kind}
	}
	final := snapshot.final
	if final == "" {
		final = Direct
	}
	return Decision{Target: final, RuleIndex: -1, Match: MatchDefault}
}

// Router atomically publishes compiled route snapshots.
type Router struct{ snapshot atomic.Pointer[Snapshot] }

// NewRouter creates a router from a validated immutable snapshot.
func NewRouter(snapshot *Snapshot) *Router {
	router := &Router{}
	router.snapshot.Store(snapshot)
	return router
}

// Snapshot returns the active immutable route snapshot.
func (router *Router) Snapshot() *Snapshot { return router.snapshot.Load() }

// Replace compiles the configuration and publishes it as the new route snapshot.
func (router *Router) Replace(config Config) error {
	candidate, err := Compile(config)
	if err != nil {
		return err
	}
	router.snapshot.Store(candidate)
	return nil
}

// Route selects a target using the active snapshot and generation-local DNS availability.
func (router *Router) Route(ctx context.Context, request Request) Decision {
	snapshot := router.Snapshot()
	finish := func(decision Decision) Decision { return snapshot.finish(request, decision) }
	if request.Network == UDP && request.Port == 53 && DNSPacketExchangerFromContext(ctx) != nil {
		return finish(Decision{Target: DNS, RuleIndex: -1, Match: MatchDNS})
	}
	domain := normalizeDomain(request.Domain)
	best, kind := snapshot.matchDomain(domain, len(snapshot.rules))
	if address := requestAddress(request, domain); address.IsValid() {
		best, kind = snapshot.matchAddress(address, best, kind)
		return finish(snapshot.decision(best, kind))
	}
	decision := snapshot.decision(best, kind)
	if snapshot.earliestIPRule >= best {
		return finish(decision)
	}
	resolver := NameResolverFromContext(ctx)
	if resolver == nil {
		return finish(decision)
	}
	decision.DNSAttempted = true
	addresses, err := resolver.LookupIP(ctx, domain)
	if err != nil {
		decision.ResolveError = err
		return finish(decision)
	}
	if len(addresses) == 0 {
		decision.ResolveError = &net.DNSError{Name: domain, Err: "no addresses"}
		return finish(decision)
	}
	decision.Resolved = true
	decision.Addresses = addresses
	for _, address := range addresses {
		if !address.IsValid() {
			continue
		}
		best, kind = snapshot.matchAddress(address.Unmap(), best, kind)
		if best == snapshot.earliestIPRule {
			break
		}
	}
	resolved := snapshot.decision(best, kind)
	resolved.Resolved = true
	resolved.DNSAttempted = true
	resolved.Addresses = decision.Addresses
	return finish(resolved)
}

func snapshotHash(rules []rule) string {
	var builder strings.Builder
	for _, rule := range rules {
		builder.WriteString(string(rule.target))
		builder.WriteByte('\n')
		for _, identity := range rule.selectors.identities {
			builder.WriteString(identity)
			builder.WriteByte('\n')
		}
	}
	sum := sha256.Sum256([]byte(builder.String()))
	return hex.EncodeToString(sum[:])
}
