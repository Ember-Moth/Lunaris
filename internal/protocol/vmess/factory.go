// SPDX-License-Identifier: GPL-3.0-only
package vmess

import (
	"errors"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/Ember-Moth/Lunaris/internal/protocol/stream"
	"github.com/Ember-Moth/Lunaris/internal/transport"
	upstream "github.com/sagernet/sing-vmess"
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
	// Allow fragmented header reads; upstream AEAD and replay checks stay enabled.
	s := upstream.NewService[string](d.Handler, upstream.ServiceWithDisableHeaderProtection())
	if err := s.UpdateUsers(r.Spec.CredentialRefs, stream.Passwords(r), make([]int, len(r.Spec.CredentialRefs))); err != nil {
		return transport.Binding{}, errors.New("invalid VMess users")
	}
	return transport.Binding{Stream: &transport.StreamHandler{Serve: s.NewConnection, Start: s.Start, Close: s.Close}}, nil
}
