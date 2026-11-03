// SPDX-License-Identifier: GPL-3.0-only
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	dnsmod "github.com/Ember-Moth/Lunaris/internal/dns"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/route"
)

type prepared struct {
	routes  *route.Snapshot
	dns     *dnsmod.Snapshot
	options dnsmod.Options
	hijack  bool
}

// Normalize owns configuration containers; large GeoData materials are immutable.
func Normalize(snapshot *model.RuntimeConfig) error {
	cfg := &snapshot.Config
	cfg.GeoData = maps.Clone(cfg.GeoData)
	snapshot.GeoData = maps.Clone(snapshot.GeoData)
	if len(cfg.GeoData) == 0 {
		cfg.GeoData = nil
	}
	if len(snapshot.GeoData) == 0 {
		snapshot.GeoData = nil
	}
	if len(cfg.GeoData) > 2 || len(cfg.GeoData) != len(snapshot.GeoData) {
		return errors.New("geodata bindings and materials disagree")
	}
	for kind, id := range cfg.GeoData {
		material := snapshot.GeoData[kind]
		if (kind != "geosite" && kind != "geoip") || id == "" || len(id) > 128 || material == nil || material.Size() == 0 || material.Size() > model.MaxGeoDataSize {
			return errors.New("invalid geodata binding")
		}
	}
	if cfg.Route != nil {
		copy := *cfg.Route
		copy.Block = slices.Clone(copy.Block)
		copy.Rules = slices.Clone(copy.Rules)
		if len(copy.Block) > 8192 || len(copy.Rules) > 4096 {
			return errors.New("too many route rules")
		}
		if err := selectors(copy.Block); err != nil {
			return err
		}
		for i := range copy.Rules {
			copy.Rules[i].Match = slices.Clone(copy.Rules[i].Match)
			if (copy.Rules[i].Action != "direct" && copy.Rules[i].Action != "block") || len(copy.Rules[i].Match) == 0 {
				return fmt.Errorf("route rule %d requires direct/block and a match", i)
			}
			if err := selectors(copy.Rules[i].Match); err != nil {
				return err
			}
		}
		cfg.Route = &copy
	}
	if cfg.DNS != nil {
		copy := *cfg.DNS
		copy.Servers = slices.Clone(copy.Servers)
		if len(copy.Servers) > 64 {
			return errors.New("too many DNS servers")
		}
		switch copy.Strategy {
		case "":
			copy.Strategy = "prefer_ipv4"
		case "prefer_ipv4", "prefer_ipv6", "only_ipv4", "only_ipv6":
		default:
			return errors.New("invalid DNS strategy")
		}
		if copy.Timeout == 0 {
			copy.Timeout = 5 * time.Second
		}
		if copy.Timeout < time.Millisecond || copy.Timeout > time.Minute {
			return errors.New("DNS timeout must be between 1ms and 1m")
		}
		if copy.SystemCacheTTL == 0 {
			copy.SystemCacheTTL = time.Minute
		}
		if copy.SystemCacheTTL < time.Second || copy.SystemCacheTTL > 24*time.Hour {
			return errors.New("system DNS cache TTL must be between 1s and 24h")
		}
		for i := range copy.Servers {
			server := &copy.Servers[i]
			server.Domains = slices.Clone(server.Domains)
			if server.Proto == "" {
				server.Proto = "udp"
			}
			switch server.Proto {
			case "udp", "tcp", "tls", "https":
			default:
				return errors.New("DNS supports udp, tcp, tls and https")
			}
			if len(server.Address) > 2048 || len(server.ServerName) > 253 || strings.ContainsAny(server.ServerName, " /\\\r\n\t") {
				return errors.New("invalid DNS endpoint")
			}
			for _, selector := range server.Domains {
				lower := strings.ToLower(strings.TrimSpace(selector))
				if strings.HasPrefix(lower, "geoip:") || strings.HasPrefix(lower, "ip:") || strings.HasPrefix(lower, "cidr:") {
					return errors.New("DNS selectors must match domains")
				}
			}
			if err := selectors(server.Domains); err != nil {
				return err
			}
		}
		cfg.DNS = &copy
	}
	if cfg.Route == nil && cfg.DNS == nil && len(cfg.GeoData) == 0 {
		snapshot.PolicyDigest = ""
		return nil
	}
	p, err := compile(snapshot)
	if err != nil {
		return err
	}
	snapshot.PolicyDigest = ""
	if cfg.Route != nil || cfg.DNS != nil || len(cfg.GeoData) > 0 {
		raw, _ := json.Marshal(struct {
			Route, DNS string
			Config     model.DNSConfig
			Assets     map[string]string
		}{Route: p.routes.Hash(), DNS: p.dns.Hash(), Config: dnsConfig(snapshot), Assets: cfg.GeoData})
		sum := sha256.Sum256(raw)
		snapshot.PolicyDigest = hex.EncodeToString(sum[:])
	}
	return nil
}
func selectors(values []string) error {
	if len(values) > 8192 {
		return errors.New("too many selectors")
	}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			return errors.New("empty routing selector")
		}
		if _, err := netip.ParseAddr(trimmed); err != nil {
			if _, err := netip.ParsePrefix(trimmed); err != nil {
				if prefix, _, ok := strings.Cut(trimmed, ":"); ok {
					switch strings.ToLower(prefix) {
					case "full", "suffix", "domain", "keyword", "plain", "regex", "regexp", "geosite", "geoip", "ip", "cidr":
					default:
						return errors.New("unsupported selector prefix")
					}
				}
			}
		}
		if len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n") {
			return errors.New("invalid routing selector")
		}
	}
	return nil
}
func dnsConfig(snapshot *model.RuntimeConfig) model.DNSConfig {
	if snapshot.Config.DNS != nil {
		return *snapshot.Config.DNS
	}
	return model.DNSConfig{Strategy: "prefer_ipv4", Timeout: 5 * time.Second, SystemCacheTTL: time.Minute}
}
func compile(snapshot *model.RuntimeConfig) (*prepared, error) {
	catalog, err := route.NewCatalog(snapshot.GeoData)
	if err != nil {
		return nil, err
	}
	routing := route.Config{GeoData: catalog}
	if value := snapshot.Config.Route; value != nil {
		routing.Block = value.Block
		routing.Rules = value.Rules
	}
	routes, err := route.Compile(routing)
	if err != nil {
		return nil, err
	}
	config := dnsConfig(snapshot)
	dns, err := dnsmod.Compile(dnsmod.Config{Servers: config.Servers, GeoData: catalog})
	if err != nil {
		return nil, err
	}
	return &prepared{routes: routes, dns: dns, options: dnsmod.Options{Timeout: config.Timeout, Preference: dnsmod.Preference(config.Strategy), SystemLookupTTL: config.SystemCacheTTL}, hijack: config.HijackUDP53}, nil
}
