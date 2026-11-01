// SPDX-License-Identifier: GPL-3.0-only
// Package inbound composes independent protocol and transport registries.
package inbound

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/Ember-Moth/Lunaris/internal/extension"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/Ember-Moth/Lunaris/internal/transport"
	"github.com/sagernet/sing/common/logger"
)

type Registry struct {
	protocols  *protocol.Registry
	transports *transport.Registry
}

func NewRegistry(protocols *protocol.Registry, transports *transport.Registry) (*Registry, error) {
	if protocols == nil || transports == nil {
		return nil, errors.New("protocol and transport registries are required")
	}
	for _, p := range protocols.Capabilities() {
		if len(p.Transports) == 0 {
			return nil, fmt.Errorf("protocol %q has no transport", p.Type)
		}
		seen := map[string]bool{}
		for _, name := range p.Transports {
			if seen[name] {
				return nil, fmt.Errorf("protocol %q has duplicate transport %q", p.Type, name)
			}
			seen[name] = true
			if _, ok := transports.Lookup(name); !ok {
				return nil, fmt.Errorf("protocol %q references unregistered transport %q", p.Type, name)
			}
		}
	}
	return &Registry{protocols: protocols, transports: transports}, nil
}
func (r *Registry) Protocols() *protocol.Registry   { return r.protocols }
func (r *Registry) Transports() *transport.Registry { return r.transports }
func (r *Registry) factories(s model.ListenerSpec) (protocol.Factory, transport.Factory, error) {
	p, ok := r.protocols.Lookup(s.Protocol)
	if !ok {
		return nil, nil, fmt.Errorf("unsupported protocol %q", s.Protocol)
	}
	c := p.Capabilities()
	kind := s.Transport.Type
	if kind == "" {
		kind = c.Transports[0]
	}
	if !slices.Contains(c.Transports, kind) {
		return nil, nil, fmt.Errorf("protocol %q does not support transport %q", s.Protocol, kind)
	}
	t, ok := r.transports.Lookup(kind)
	if !ok {
		return nil, nil, fmt.Errorf("unregistered transport %q", kind)
	}
	tc := t.Capabilities()
	if !(c.TCP && tc.TCP || c.UDP && tc.UDP) {
		return nil, nil, errors.New("protocol and transport have no common listening network")
	}
	for _, network := range s.Network {
		if (network == "tcp" && (!c.TCP || !tc.TCP)) || (network == "udp" && (!c.UDP || !tc.UDP)) || (network != "tcp" && network != "udp") {
			return nil, nil, errors.New("network is incompatible with protocol and transport")
		}
	}
	if s.CertificateRef != "" && (!c.TLS || !tc.TLS) {
		return nil, nil, errors.New("TLS is unsupported by this protocol and transport combination")
	}
	if c.TLSRequired && s.CertificateRef == "" && !tc.Secure {
		return nil, nil, errors.New("protocol requires a TLS certificate")
	}
	uotEnabled := s.UDPOverTCP || c.UDPOverTCPRequired
	if uotEnabled && !c.UDPOverTCP {
		return nil, nil, errors.New("protocol does not support UDP over TCP")
	}
	if s.Multiplex.Enabled && !c.Multiplex {
		return nil, nil, errors.New("protocol does not support sing-mux")
	}
	if (s.Multiplex.Enabled || uotEnabled) && len(s.Network) > 0 && !slices.Contains(s.Network, "tcp") && !tc.UDPStreams {
		return nil, nil, errors.New("connection extensions require a TCP listening network")
	}
	if s.Multiplex.Padding && !s.Multiplex.Enabled {
		return nil, nil, errors.New("multiplex.padding requires multiplex.enabled")
	}
	if fields := t.Validate(s); len(fields) > 0 {
		return nil, nil, fmt.Errorf("%s: %s", fields[0].Path, fields[0].Message)
	}
	return p, t, nil
}

// Build assembles protocol callbacks with a selected carrier. Neither factory
// owns the other registry; all compatibility checks happen before construction.
func (r *Registry) Build(s protocol.ResolvedListenerSpec, d protocol.Dependencies) (protocol.Instance, error) {
	if err := model.ValidateLimits(s.Limits); err != nil {
		return nil, err
	}
	p, t, err := r.factories(s.Spec)
	if err != nil {
		return nil, err
	}
	if fields := p.Validate(s.Spec); len(fields) > 0 {
		return nil, errors.New(fields[0].Message)
	}
	// Certificates belong to the carrier; protocol constructors only receive
	// their credential material and the logical TLS policy in ListenerSpec.
	protocolSpec := s
	protocolSpec.Certificate, protocolSpec.PrivateKey = nil, nil
	protocolSpec.Credentials = credentialSubset(s.Credentials, protocolCredentialRefs(p, s.Spec))
	if v, ok := p.(protocol.AssetValidator); ok {
		if err := v.ValidateAssets(protocolSpec); err != nil {
			return nil, err
		}
	}
	if d.Handler == nil {
		return nil, errors.New("relay handler required")
	}
	if d.Logger == nil {
		d.Logger = logger.NOP()
	}
	networks := slices.Clone(s.Spec.Network)
	if len(networks) == 0 {
		c := t.Capabilities()
		pc := p.Capabilities()
		if c.TCP && pc.TCP {
			networks = append(networks, "tcp")
		}
		if c.UDP && pc.UDP {
			networks = append(networks, "udp")
		}
	}
	resolved := transport.ResolvedSpec{Address: s.Spec.Address, Port: s.Spec.Port, Network: networks, Transport: s.Spec.Transport, Limits: s.Limits}
	if s.Spec.CertificateRef != "" {
		resolved.Certificate, resolved.PrivateKey = bytes.Clone(s.Certificate), bytes.Clone(s.PrivateKey)
		if len(resolved.Certificate) == 0 || len(resolved.PrivateKey) == 0 {
			return nil, errors.New("resolved certificate and private key required")
		}
	}
	if assets, ok := t.(transport.AssetFactory); ok {
		resolved.Secrets = credentialSubset(s.Credentials, assets.CredentialRefs(s.Spec))
		if err := assets.ValidateAssets(resolved); err != nil {
			return nil, err
		}
	}
	caps := p.Capabilities()
	extensions, err := extension.New(extension.Options{UDPOverTCP: s.Spec.UDPOverTCP || caps.UDPOverTCPRequired, UDPOverTCPVersion: caps.UDPOverTCPVersion, Multiplex: s.Spec.Multiplex}, s.Limits, d.Handler, d.Logger)
	if err != nil {
		return nil, err
	}
	d.Handler = transport.Bridge{Handler: extensions}
	binding, err := p.Build(protocolSpec, d)
	if err != nil {
		_ = extensions.Close(context.Background())
		return nil, err
	}
	instance, err := t.Build(resolved, binding)
	if err != nil {
		_ = extensions.Close(context.Background())
		return nil, err
	}
	return &extension.Instance{Instance: instance, Handler: extensions}, nil
}

func (r *Registry) CredentialRefs(s model.ListenerSpec) []string {
	refs := slices.Clone(s.CredentialRefs)
	p, ok := r.protocols.Lookup(s.Protocol)
	if !ok {
		return refs
	}
	refs = protocolCredentialRefs(p, s)
	kind := s.Transport.Type
	if kind == "" {
		kind = p.Capabilities().Transports[0]
	}
	if f, ok := r.transports.Lookup(kind); ok {
		if a, ok := f.(transport.AssetFactory); ok {
			for _, ref := range a.CredentialRefs(s) {
				if !slices.Contains(refs, ref) {
					refs = append(refs, ref)
				}
			}
		}
	}
	return refs
}
func credentialSubset(input map[string][]byte, refs []string) map[string][]byte {
	out := make(map[string][]byte, len(refs))
	for _, ref := range refs {
		out[ref] = bytes.Clone(input[ref])
	}
	return out
}

func protocolCredentialRefs(p protocol.Factory, s model.ListenerSpec) []string {
	refs := slices.Clone(s.CredentialRefs)
	if assets, ok := p.(protocol.CredentialReferencer); ok {
		for _, ref := range assets.CredentialRefs(s) {
			if !slices.Contains(refs, ref) {
				refs = append(refs, ref)
			}
		}
	}
	return refs
}
