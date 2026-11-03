// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors
// Adapted from Polaris 56d52fb44958ef3cc2a7fb841cd240f8206234b2.
// Package dns provides product-owned DNS parsing, transport, and caching.
package dns

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/route"
)

// Preference selects the preferred address family for lookups.
type Preference string

// Address family preferences for resolver results.
const (
	PreferIPv4 Preference = "prefer_ipv4"
	PreferIPv6 Preference = "prefer_ipv6"
	OnlyIPv4   Preference = "only_ipv4"
	OnlyIPv6   Preference = "only_ipv6"
)

// ParsePreference accepts PPanel and Xray-compatible IP strategy spellings.
func ParsePreference(value string) (Preference, error) {
	normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "_", ""))
	switch normalized {
	case "", "useip", "usesystem", "preferipv4", "useipv4v6":
		return PreferIPv4, nil
	case "preferipv6", "useipv6v4":
		return PreferIPv6, nil
	case "useipv4", "onlyipv4", "ipv4only", "ipv4":
		return OnlyIPv4, nil
	case "useipv6", "onlyipv6", "ipv6only", "ipv6":
		return OnlyIPv6, nil
	default:
		return "", fmt.Errorf("dns: unsupported IP strategy %q", value)
	}
}

type transport uint8

const (
	transportUDP transport = iota
	transportTCP
	transportTLS
	transportHTTPS
)

type server struct {
	transport  transport
	address    string
	serverName string
	selectors  []route.DomainMatcher
}

// Config is the application DNS configuration boundary.
type Config struct {
	Servers []model.DNSServer
	GeoData *route.Catalog
}

// Snapshot is immutable validated DNS configuration with a generation-local cache.
type Snapshot struct {
	servers []server
	hash    string
	cache   *cache
}

// Compile validates DNS servers before a runtime publishes the snapshot.
func Compile(config Config) (*Snapshot, error) {
	servers := make([]server, 0, len(config.Servers))
	for index, item := range config.Servers {
		parsed, err := parseServer(item, config.GeoData)
		if err != nil {
			return nil, fmt.Errorf("dns: server %d: %w", index, err)
		}
		servers = append(servers, parsed)
	}
	return &Snapshot{servers: servers, hash: hashServers(servers), cache: newCache()}, nil
}

// MustCompile is for trusted defaults and tests.
func MustCompile(config Config) *Snapshot {
	snapshot, err := Compile(config)
	if err != nil {
		panic(err)
	}
	return snapshot
}

// Hash identifies this immutable DNS configuration without copying secrets.
func (snapshot *Snapshot) Hash() string { return snapshot.hash }

func (snapshot *Snapshot) selectServer(name string) (server, error) {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	var defaultServer *server
	for _, server := range snapshot.servers {
		if len(server.selectors) == 0 {
			candidate := server
			defaultServer = &candidate
			continue
		}
		for _, selector := range server.selectors {
			if selector.MatchNormalized(name) {
				return server, nil
			}
		}
	}
	if defaultServer != nil {
		return *defaultServer, nil
	}
	return server{}, ErrNoConfiguredResolver
}

func parseServer(item model.DNSServer, catalogs ...*route.Catalog) (server, error) {
	selectors, err := route.CompileDomainMatchers(item.Domains, catalogs...)
	if err != nil {
		return server{}, err
	}
	protocol := strings.ToLower(strings.TrimSpace(item.Proto))
	if protocol == "" {
		protocol = "udp"
	}
	parsed := server{
		address:    strings.TrimSpace(item.Address),
		serverName: strings.TrimSpace(item.ServerName),
		selectors:  selectors,
	}
	switch protocol {
	case "udp":
		parsed.transport = transportUDP
	case "tcp":
		parsed.transport = transportTCP
	case "tls", "dot":
		parsed.transport = transportTLS
	case "https", "doh":
		parsed.transport = transportHTTPS
	case "quic", "doq":
		return server{}, errors.New("QUIC DNS is unsupported")
	default:
		return server{}, fmt.Errorf("unsupported DNS protocol %q", item.Proto)
	}
	if parsed.address == "" {
		return server{}, errors.New("empty address")
	}
	if parsed.transport == transportHTTPS {
		endpoint, parseErr := url.Parse(parsed.address)
		if parseErr != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.Fragment != "" || endpoint.RawQuery != "" {
			return server{}, errors.New("invalid HTTPS DNS address")
		}
		if port := endpoint.Port(); port != "" {
			n, err := strconv.Atoi(port)
			if err != nil || n < 1 || n > 65535 {
				return server{}, errors.New("invalid HTTPS DNS port")
			}
		}
		return parsed, nil
	}
	host, port, splitErr := net.SplitHostPort(parsed.address)
	number, portErr := strconv.Atoi(port)
	if splitErr != nil || host == "" || portErr != nil || number < 1 || number > 65535 {
		return server{}, fmt.Errorf("invalid DNS address %q", parsed.address)
	}
	if parsed.transport == transportTLS {
		if parsed.serverName == "" && net.ParseIP(host) == nil {
			parsed.serverName = host
		}
		if parsed.serverName == "" {
			return server{}, errors.New("DoT address requires an explicit hostname")
		}
		return parsed, nil
	}
	return parsed, nil
}

func hashServers(servers []server) string {
	var builder strings.Builder
	for _, server := range servers {
		builder.WriteString(strconv.Itoa(int(server.transport)))
		builder.WriteByte(':')
		builder.WriteString(server.address)
		builder.WriteByte(':')
		builder.WriteString(server.serverName)
		for _, selector := range server.selectors {
			builder.WriteByte(':')
			builder.WriteString(selector.Key())
		}
		builder.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(builder.String()))
	return hex.EncodeToString(sum[:])
}
