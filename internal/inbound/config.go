// SPDX-License-Identifier: GPL-3.0-only
package inbound

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/Ember-Moth/Lunaris/internal/transport"
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
	if err := model.ValidateLimits(input.Config.Limits); err != nil {
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
		factory, ok := r.protocols.Lookup(spec.Protocol)
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
		if caps.UDPOverTCPRequired {
			spec.UDPOverTCP = true
		}
		spec.Transport = spec.Transport.Clone()
		if spec.Transport.Type == "" && len(caps.Transports) > 0 {
			if caps.Transports[0] != "native" {
				spec.Transport.Type = caps.Transports[0]
			}
		}
		if spec.CertificateRef != "" {
			if _, exists := result.Certificates[spec.CertificateRef]; !exists {
				return nil, fmt.Errorf("listener %q: unknown certificate reference", spec.ID)
			}
		}
		spec.Network = slices.Clone(spec.Network)
		_, carrier, err := r.factories(spec)
		if err != nil {
			return nil, fmt.Errorf("listener %q: %w", spec.ID, err)
		}
		transportCaps := transport.CapabilitiesFor(carrier, spec)
		udp := caps.UDP || (caps.TCP && transportCaps.UDPStreams)
		if len(spec.Network) == 0 {
			if caps.TCP && transportCaps.TCP {
				spec.Network = append(spec.Network, "tcp")
			}
			if udp && transportCaps.UDP {
				spec.Network = append(spec.Network, "udp")
			}
		}
		if len(spec.Network) == 0 {
			return nil, fmt.Errorf("listener %q: protocol has no supported network", spec.ID)
		}
		slices.Sort(spec.Network)
		for i, network := range spec.Network {
			if (network != "tcp" && network != "udp") || (network == "tcp" && !caps.TCP) || (network == "udp" && !udp) || (i > 0 && spec.Network[i-1] == network) {
				return nil, fmt.Errorf("listener %q: invalid or unsupported network", spec.ID)
			}
		}
		if _, _, err := r.factories(spec); err != nil {
			return nil, fmt.Errorf("listener %q: %w", spec.ID, err)
		}
		spec.CredentialRefs = slices.Clone(spec.CredentialRefs)
		for _, ref := range r.CredentialRefs(spec) {
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
		if validator, ok := factory.(protocol.AssetValidator); ok {
			if err := validator.ValidateAssets(protocol.ResolvedListenerSpec{Spec: spec, Limits: result.Config.Limits, Credentials: credentialSubset(result.Credentials, protocolCredentialRefs(factory, spec))}); err != nil {
				return nil, fmt.Errorf("listener %q: %w", spec.ID, err)
			}
		}
		if validator, ok := carrier.(transport.AssetFactory); ok {
			if err := validator.ValidateAssets(transport.ResolvedSpec{Transport: spec.Transport, Limits: result.Config.Limits, Secrets: credentialSubset(result.Credentials, validator.CredentialRefs(spec))}); err != nil {
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
