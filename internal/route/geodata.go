// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors
// Category semantics and built-in private prefixes adapted from Polaris.
package route

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"github.com/Ember-Moth/Lunaris/internal/model"
)

const maxGeoDataSize = model.MaxGeoDataSize
const maxExpandedSelectors = 1_000_000

type geoDataKind uint8

const (
	geoDataSite geoDataKind = iota
	geoDataIP
)

type geoSiteCategory struct {
	code       string
	attributes []string
	key        string
}
type geoDataVersion struct {
	path string
	size int64
	kind geoDataKind
}
type catalogAsset struct {
	entries map[string][][]byte
	version geoDataVersion
}

// Catalog is compilation-local. It reads only the immutable assets supplied by
// the repository, never paths, environment variables, or process-wide files.
type Catalog struct {
	assets          map[geoDataKind]catalogAsset
	sites           map[string]*domainSet
	ips             map[string]*prefixSet
	expanded, nodes int
}

var privatePrefixSetOnce sync.Once
var privatePrefixSet *prefixSet

func builtInPrivatePrefixSet() *prefixSet {
	privatePrefixSetOnce.Do(func() { privatePrefixSet = newPrefixSet(privatePrefixes()) })
	return privatePrefixSet
}
func dataKind(kind string) (geoDataKind, error) {
	switch kind {
	case "geosite":
		return geoDataSite, nil
	case "geoip":
		return geoDataIP, nil
	default:
		return 0, errors.New("route: unsupported geodata kind")
	}
}
func NewCatalog(materials map[string]*model.GeoDataMaterial) (*Catalog, error) {
	c := &Catalog{assets: map[geoDataKind]catalogAsset{}, sites: map[string]*domainSet{}, ips: map[string]*prefixSet{}}
	for name, material := range materials {
		kind, err := dataKind(name)
		if err != nil {
			return nil, err
		}
		if material == nil || material.Size() == 0 || material.Size() > maxGeoDataSize {
			return nil, errors.New("route: invalid geodata asset size")
		}
		data, err := io.ReadAll(material.Open())
		if err != nil {
			return nil, err
		}
		entries, err := indexGeoDataEntries(data, kind)
		if err != nil {
			return nil, err
		}
		if len(entries) > 4096 {
			return nil, errors.New("route: too many geodata categories")
		}
		c.assets[kind] = catalogAsset{entries: entries, version: geoDataVersion{path: name + ":" + material.Digest(), size: int64(material.Size()), kind: kind}}
	}
	return c, nil
}
func ValidateGeoData(name string, data []byte) error {
	kind, err := dataKind(name)
	if err != nil {
		return err
	}
	if len(data) == 0 || len(data) > maxGeoDataSize {
		return errors.New("route: invalid geodata size")
	}
	entries, err := indexGeoDataEntries(data, kind)
	if err != nil {
		return err
	}
	if len(entries) == 0 || len(entries) > 4096 {
		return errors.New("route: invalid geodata category count")
	}
	for _, values := range entries {
		for _, entry := range values {
			if kind == geoDataSite {
				if _, err := parseGeoSiteEntry(entry, nil); err != nil {
					return err
				}
			} else {
				if _, err := parseGeoIPEntry(entry); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
func (c *Catalog) asset(kind geoDataKind) (catalogAsset, error) {
	if c != nil {
		if a, ok := c.assets[kind]; ok {
			return a, nil
		}
	}
	return catalogAsset{}, errors.New("route: referenced geodata asset is missing")
}
func (c *Catalog) siteSelectors(raw string) ([]Selector, error) {
	category, err := parseGeoSiteCategory(raw)
	if err != nil {
		return nil, err
	}
	a, err := c.asset(geoDataSite)
	if err != nil {
		return nil, err
	}
	entries := a.entries[category.code]
	if len(entries) == 0 {
		return nil, fmt.Errorf("route: geosite category %q not found", category.code)
	}
	return parseGeoSiteEntry(entries[0], category.attributes)
}
func (c *Catalog) loadSite(raw string) (*domainSet, error) {
	category, err := parseGeoSiteCategory(raw)
	if err != nil {
		return nil, err
	}
	if c != nil {
		if set, ok := c.sites[category.key]; ok {
			return set, nil
		}
	}
	selectors, err := c.siteSelectors(raw)
	if err != nil {
		return nil, err
	}
	if len(selectors)+c.expanded > maxExpandedSelectors {
		return nil, errors.New("route: expanded selector budget exceeded")
	}
	c.expanded += len(selectors)
	set := newDomainSet(selectors)
	if set == nil {
		set = &domainSet{hash: hashDomainSelectors(nil)}
	}
	set.source = c.assets[geoDataSite].version
	c.sites[category.key] = set
	return set, nil
}
func (c *Catalog) loadIP(code string) (*prefixSet, error) {
	if c != nil {
		if set, ok := c.ips[code]; ok {
			return set, nil
		}
	}
	a, err := c.asset(geoDataIP)
	if err != nil {
		return nil, err
	}
	entries := a.entries[code]
	if len(entries) == 0 {
		return nil, fmt.Errorf("route: geoip category %q not found", code)
	}
	var prefixes []netip.Prefix
	for _, entry := range entries {
		items, err := parseGeoIPEntry(entry)
		if err != nil {
			return nil, err
		}
		if len(prefixes)+len(items)+c.expanded > maxExpandedSelectors {
			return nil, errors.New("route: expanded prefix budget exceeded")
		}
		prefixes = append(prefixes, items...)
	}
	c.expanded += len(prefixes)
	if c.nodes >= 2_000_000 {
		return nil, errors.New("route: prefix index budget exceeded")
	}
	set, err := newPrefixSetBounded(prefixes, 2_000_000-c.nodes)
	if err != nil {
		return nil, err
	}
	if set == nil {
		set = &prefixSet{nodes: make([]prefixNode, 2), ipv4Root: 0, ipv6Root: 1, hash: hashIPPrefixes(nil)}
	}
	c.nodes += len(set.nodes)
	set.source = a.version
	c.ips[code] = set
	return set, nil
}
func parseGeoSiteCategory(raw string) (geoSiteCategory, error) {
	parts := strings.Split(raw, "@")
	code, err := normalizeGeoCategory(parts[0])
	if err != nil {
		return geoSiteCategory{}, err
	}
	attributes := make([]string, 0, len(parts)-1)
	seen := make(map[string]struct{}, len(parts)-1)
	for _, rawAttribute := range parts[1:] {
		attribute := strings.ToLower(strings.TrimSpace(rawAttribute))
		if attribute == "" {
			continue
		}
		if _, loaded := seen[attribute]; loaded {
			continue
		}
		seen[attribute] = struct{}{}
		attributes = append(attributes, attribute)
	}
	slices.Sort(attributes)
	key := code
	if len(attributes) > 0 {
		key += "@" + strings.Join(attributes, "@")
	}
	return geoSiteCategory{code: code, attributes: attributes, key: key}, nil
}

func normalizeGeoCategory(category string) (string, error) {
	category = strings.ToUpper(strings.TrimSpace(category))
	if category == "" {
		return "", errors.New("route: empty geodata category")
	}
	if strings.Contains(category, "@") {
		return "", fmt.Errorf("route: invalid geodata category %q", category)
	}
	return category, nil
}

func privatePrefixes() []netip.Prefix {
	values := []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "2001:db8::/32",
	}
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefixes = append(prefixes, netip.MustParsePrefix(value))
	}
	return prefixes
}

// reset closes mappings owned by this registry. It is intentionally unexported;
// tests use a private registry or reset the process-wide one between asset swaps.
