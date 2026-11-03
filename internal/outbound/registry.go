// SPDX-License-Identifier: GPL-3.0-only
// Package outbound constructs protocol clients using the released sing libraries.
package outbound

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"

	"github.com/Ember-Moth/Lunaris/internal/model"
	N "github.com/sagernet/sing/common/network"
)

var ErrUnsupportedNetwork = errors.New("outbound does not support this network")

type Capabilities struct {
	Protocol string   `json:"protocol"`
	TCP      bool     `json:"tcp"`
	UDP      bool     `json:"udp"`
	Methods  []string `json:"methods,omitempty"`
}

type Client interface {
	N.Dialer
	Close(context.Context) error
}

type ProtocolClient interface {
	N.Dialer
	io.Closer
}

type Factory interface {
	Capabilities() Capabilities
	Normalize(model.OutboundSpec, []byte) (json.RawMessage, error)
	Build(context.Context, model.OutboundSpec, []byte, N.Dialer, model.Limits) (ProtocolClient, error)
}

// Registry is immutable after construction; protocol registration is explicit.
type Registry struct{ factories map[string]Factory }

func NewRegistry() *Registry {
	r := &Registry{factories: make(map[string]Factory)}
	for _, f := range []Factory{socksFactory{}, socksFactory{kind: "socks4"}, socksFactory{kind: "socks4a"}, httpFactory{}, shadowsocksFactory{}, vmessFactory{}, vlessFactory{}, trojanFactory{}, anytlsFactory{}, hysteriaFactory{}, tuicFactory{}} {
		r.factories[f.Capabilities().Protocol] = f
	}
	return r
}

func (r *Registry) Capabilities() []Capabilities {
	result := make([]Capabilities, 0, len(r.factories))
	for _, f := range r.factories {
		result = append(result, f.Capabilities())
	}
	slices.SortFunc(result, func(a, b Capabilities) int { return strings.Compare(a.Protocol, b.Protocol) })
	return result
}

func ValidID(id string) bool {
	if id == "" || len(id) > 64 || id == "direct" || id == "block" || id == "dns" {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func (r *Registry) Normalize(spec model.OutboundSpec, credentials map[string][]byte) (model.OutboundSpec, error) {
	if !ValidID(spec.ID) || len(spec.Name) > 256 {
		return spec, errors.New("invalid outbound id or name")
	}
	switch spec.Protocol {
	case "socks":
		spec.Protocol = "socks5"
	case "hysteria":
		spec.Protocol = "hysteria2"
	}
	f, ok := r.factories[spec.Protocol]
	if !ok {
		return spec, errors.New("unsupported outbound protocol")
	}
	if spec.Port == 0 || spec.Address == "" || len(spec.Address) > 253 || strings.ContainsAny(spec.Address, " /\\@\r\n\t\x00[]") {
		return spec, errors.New("invalid outbound endpoint")
	}
	if ip, err := netip.ParseAddr(spec.Address); err == nil {
		if ip.IsUnspecified() || ip.IsMulticast() || ip.Zone() != "" {
			return spec, errors.New("invalid outbound IP address")
		}
		spec.Address = ip.Unmap().String()
	} else {
		spec.Address = strings.ToLower(strings.TrimSuffix(spec.Address, "."))
		for _, label := range strings.Split(spec.Address, ".") {
			if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return spec, errors.New("invalid outbound hostname")
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return spec, errors.New("invalid outbound hostname")
				}
			}
		}
	}
	var secret []byte
	if spec.CredentialRef != "" {
		secret = credentials[spec.CredentialRef]
		if len(spec.CredentialRef) > 128 || len(secret) == 0 || len(secret) > 4096 {
			return spec, errors.New("invalid outbound credential reference")
		}
	}
	options, err := f.Normalize(spec, secret)
	if err != nil {
		return spec, fmt.Errorf("outbound %q: %w", spec.ID, err)
	}
	spec.Options = options
	return spec, nil
}

func (r *Registry) Build(ctx context.Context, spec model.OutboundSpec, credentials map[string][]byte, dialer N.Dialer, limits model.Limits) (Client, error) {
	if dialer == nil || ctx == nil {
		return nil, errors.New("outbound dialer required")
	}
	if err := model.ValidateLimits(limits); err != nil {
		return nil, err
	}
	spec, err := r.Normalize(spec, credentials)
	if err != nil {
		return nil, err
	}
	raw, err := r.factories[spec.Protocol].Build(ctx, spec, credentials[spec.CredentialRef], handshakeDialer{Dialer: dialer, timeout: limits.HandshakeTimeout}, limits)
	if err != nil {
		return nil, err
	}
	return newClient(ctx, raw, r.factories[spec.Protocol].Capabilities(), limits), nil
}

func decodeOptions(raw json.RawMessage, value any) error {
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	if len(raw) > 32768 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("invalid outbound options")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return errors.New("invalid or unsupported outbound options")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return errors.New("invalid outbound options")
	}
	return nil
}
