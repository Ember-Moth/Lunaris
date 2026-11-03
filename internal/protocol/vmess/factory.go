// SPDX-License-Identifier: GPL-3.0-only
package vmess

import (
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/Ember-Moth/Lunaris/internal/protocol/stream"
	"github.com/Ember-Moth/Lunaris/internal/transport"
)

type Factory struct{}

func (Factory) Capabilities() protocol.Capabilities {
	return protocol.Capabilities{Type: "vmess", UDPOverTCP: true, Multiplex: true, TCP: true, TCPRelay: true, UDPRelay: true, TLS: true, Transports: []string{"tcp", "ws", "httpupgrade", "reality", "xhttp"}}
}
func (Factory) Validate(s model.ListenerSpec) []model.FieldError { return stream.Validate(s) }
func (Factory) ValidateAssets(r protocol.ResolvedListenerSpec) error {
	return stream.ValidateAssets(r, true)
}
func (Factory) Build(r protocol.ResolvedListenerSpec, d protocol.Dependencies) (transport.Binding, error) {
	if err := (Factory{}).ValidateAssets(r); err != nil {
		return transport.Binding{}, err
	}
	s, err := newServer(r, d.Handler)
	if err != nil {
		return transport.Binding{}, err
	}
	// AEAD-only users do not require the upstream legacy-key ticker.
	return transport.Binding{Stream: &transport.StreamHandler{Serve: s.serve}}, nil
}
