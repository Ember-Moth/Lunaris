// SPDX-License-Identifier: GPL-3.0-only
package trojan

import (
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/Ember-Moth/Lunaris/internal/protocol/stream"
	"github.com/Ember-Moth/Lunaris/internal/transport"
)

type Factory struct{}

func (Factory) Capabilities() protocol.Capabilities {
	return protocol.Capabilities{Type: "trojan", TCP: true, TCPRelay: true, UDPRelay: true, TLS: true, TLSRequired: true, Transports: []string{"tcp", "ws", "httpupgrade"}}
}
func (Factory) Validate(s model.ListenerSpec) []model.FieldError { return stream.Validate(s) }
func (Factory) ValidateAssets(r protocol.ResolvedListenerSpec) error {
	return stream.ValidateAssets(r, false)
}
func (Factory) Build(r protocol.ResolvedListenerSpec, d protocol.Dependencies) (transport.Binding, error) {
	s := New(r.Spec.CredentialRefs, stream.Passwords(r), d.Handler)
	return transport.Binding{Stream: &transport.StreamHandler{Serve: s.NewConnection}}, nil
}
