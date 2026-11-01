// SPDX-License-Identifier: GPL-3.0-only
package vless

import (
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/Ember-Moth/Lunaris/internal/protocol/stream"
	"github.com/Ember-Moth/Lunaris/internal/transport"
	upstream "github.com/sagernet/sing-vmess/vless"
)

type Factory struct{}

func (Factory) Capabilities() protocol.Capabilities {
	return protocol.Capabilities{Type: "vless", UDPOverTCP: true, Multiplex: true, TCP: true, TCPRelay: true, UDPRelay: true, TLS: true, Transports: []string{"tcp", "ws", "httpupgrade", "reality", "xhttp"}}
}
func (Factory) Validate(s model.ListenerSpec) []model.FieldError { return stream.Validate(s) }
func (Factory) ValidateAssets(r protocol.ResolvedListenerSpec) error {
	return stream.ValidateAssets(r, true)
}
func (Factory) Build(r protocol.ResolvedListenerSpec, d protocol.Dependencies) (transport.Binding, error) {
	s := upstream.NewService[string](d.Logger, d.Handler)
	s.UpdateUsers(r.Spec.CredentialRefs, stream.Passwords(r), make([]string, len(r.Spec.CredentialRefs)))
	return transport.Binding{Stream: &transport.StreamHandler{Serve: s.NewConnection}}, nil
}
