// SPDX-License-Identifier: GPL-3.0-only
package protocol

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
)

// Normalize validates the common runtime contract and copies every mutable
// value. File mode and future application services share this validation path.
func (r *Registry) Normalize(input *model.RuntimeConfig) (*model.RuntimeConfig, error) {
	if input == nil {
		return nil, errors.New("node configuration is required")
	}
	if input.Config.SchemaVersion != model.ConfigSchemaVersion {
		return nil, errors.New("unsupported node schema_version")
	}
	if err := ValidateLimits(input.Config.Limits); err != nil {
		return nil, err
	}
	result := &model.RuntimeConfig{Config: model.NodeConfig{SchemaVersion: input.Config.SchemaVersion, Limits: input.Config.Limits, Listeners: make([]model.ListenerSpec, 0, len(input.Config.Listeners))}, Credentials: make(map[string][]byte, len(input.Credentials))}
	for id, secret := range input.Credentials {
		if id == "" || len(secret) == 0 || len(secret) > 4096 {
			return nil, errors.New("credential ids must be non-empty and secrets must contain 1 to 4096 bytes")
		}
		result.Credentials[id] = bytes.Clone(secret)
	}
	result.Certificates = make(map[string]model.Certificate, len(input.Certificates))
	for id, cert := range input.Certificates {
		if id == "" || len(cert.Certificate) > 1<<20 || len(cert.PrivateKey) > 1<<20 {
			return nil, errors.New("invalid certificate asset")
		}
		if _, err := tls.X509KeyPair(cert.Certificate, cert.PrivateKey); err != nil {
			return nil, errors.New("invalid certificate and private key pair")
		}
		result.Certificates[id] = model.Certificate{Certificate: bytes.Clone(cert.Certificate), PrivateKey: bytes.Clone(cert.PrivateKey)}
	}
	ids := make(map[string]bool)
	for _, spec := range input.Config.Listeners {
		if spec.ID == "" || ids[spec.ID] {
			return nil, errors.New("listener ids must be non-empty and unique")
		}
		ids[spec.ID] = true
		factory, ok := r.Lookup(spec.Protocol)
		if !ok {
			return nil, fmt.Errorf("listener %q: unsupported protocol %q", spec.ID, spec.Protocol)
		}
		if spec.Address == "" {
			spec.Address = "127.0.0.1"
		}
		ip, err := netip.ParseAddr(spec.Address)
		if err != nil {
			return nil, fmt.Errorf("listener %q: address must be a literal IP", spec.ID)
		}
		spec.Address = ip.String()
		if spec.Port == 0 {
			return nil, fmt.Errorf("listener %q: port must be between 1 and 65535", spec.ID)
		}
		caps := factory.Capabilities()
		if spec.Transport.Type == "" && len(caps.Transports) > 0 {
			spec.Transport.Type = caps.Transports[0]
		}
		if spec.CertificateRef != "" {
			if _, exists := result.Certificates[spec.CertificateRef]; !exists {
				return nil, fmt.Errorf("listener %q: unknown certificate reference", spec.ID)
			}
		}
		spec.Network = slices.Clone(spec.Network)
		if len(spec.Network) == 0 {
			if caps.TCP {
				spec.Network = append(spec.Network, "tcp")
			}
			if caps.UDP {
				spec.Network = append(spec.Network, "udp")
			}
		}
		if len(spec.Network) == 0 {
			return nil, fmt.Errorf("listener %q: protocol has no supported network", spec.ID)
		}
		slices.Sort(spec.Network)
		for i, network := range spec.Network {
			if (network != "tcp" && network != "udp") || (network == "tcp" && !caps.TCP) || (network == "udp" && !caps.UDP) || (i > 0 && spec.Network[i-1] == network) {
				return nil, fmt.Errorf("listener %q: invalid or unsupported network", spec.ID)
			}
		}
		spec.CredentialRefs = slices.Clone(spec.CredentialRefs)
		for _, ref := range spec.CredentialRefs {
			if _, exists := result.Credentials[ref]; !exists {
				return nil, fmt.Errorf("listener %q: unknown credential reference", spec.ID)
			}
		}
		var value any
		decoder := json.NewDecoder(bytes.NewReader(spec.Options))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			return nil, fmt.Errorf("listener %q: invalid protocol options", spec.ID)
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			return nil, fmt.Errorf("listener %q: invalid protocol options", spec.ID)
		}
		spec.Options, err = json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("listener %q: invalid protocol options", spec.ID)
		}
		if fields := factory.Validate(spec); len(fields) != 0 {
			return nil, fmt.Errorf("listener %q: %s: %s", spec.ID, fields[0].Path, fields[0].Message)
		}
		if validator, ok := factory.(AssetValidator); ok {
			cert := result.Certificates[spec.CertificateRef]
			if err := validator.ValidateAssets(ResolvedListenerSpec{Spec: spec, Limits: result.Config.Limits, Credentials: result.Credentials, Certificate: cert.Certificate, PrivateKey: cert.PrivateKey}); err != nil {
				return nil, fmt.Errorf("listener %q: %w", spec.ID, err)
			}
		}
		result.Config.Listeners = append(result.Config.Listeners, spec)
	}
	slices.SortFunc(result.Config.Listeners, func(a, b model.ListenerSpec) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	for i, a := range result.Config.Listeners {
		if !a.Enabled {
			continue
		}
		for _, b := range result.Config.Listeners[:i] {
			if !b.Enabled || a.Port != b.Port {
				continue
			}
			for _, network := range a.Network {
				if !slices.Contains(b.Network, network) {
					continue
				}
				ipA, ipB := netip.MustParseAddr(a.Address).Unmap(), netip.MustParseAddr(b.Address).Unmap()
				if ipA == ipB || ipA.IsUnspecified() || ipB.IsUnspecified() {
					return nil, fmt.Errorf("listeners %q and %q have overlapping %s endpoints", a.ID, b.ID, network)
				}
			}
		}
	}
	return result, nil
}

func ValidateLimits(l model.Limits) error {
	for name, duration := range map[string]time.Duration{"dial_timeout": l.DialTimeout, "handshake_timeout": l.HandshakeTimeout, "udp_idle_timeout": l.UDPIdleTimeout, "shutdown_timeout": l.ShutdownTimeout} {
		if duration <= 0 || duration > 24*time.Hour {
			return fmt.Errorf("%s must be positive and no greater than 24h", name)
		}
	}
	for name, count := range map[string]int{"max_connections": l.MaxConnections, "max_pending_handshakes": l.MaxPendingHandshakes, "max_udp_sessions": l.MaxUDPSessions, "max_udp_destinations": l.MaxUDPDestinations} {
		if count <= 0 || count > 65536 {
			return fmt.Errorf("%s must be between 1 and 65536", name)
		}
	}
	if l.UDPQueueSize <= 0 || l.UDPQueueSize > 1024 {
		return errors.New("udp_queue_size must be between 1 and 1024")
	}
	return nil
}
