// SPDX-License-Identifier: GPL-3.0-only
package anytls

import (
	"context"
	"net"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/Ember-Moth/Lunaris/internal/protocol/stream"
	"github.com/Ember-Moth/Lunaris/internal/transport"
	upstream "github.com/sagernet/sing-anytls"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type Factory struct{}

func (Factory) Capabilities() protocol.Capabilities {
	return protocol.Capabilities{Type: "anytls", UDPOverTCP: true, UDPOverTCPRequired: true, UDPOverTCPVersion: 2, Multiplex: false, TCP: true, TCPRelay: true, UDPRelay: true, TLS: true, TLSRequired: true, Transports: []string{"tcp", "reality"}}
}
func (Factory) Validate(s model.ListenerSpec) []model.FieldError { return stream.Validate(s) }
func (Factory) ValidateAssets(r protocol.ResolvedListenerSpec) error {
	return stream.ValidateAssets(r, false)
}
func (Factory) Build(r protocol.ResolvedListenerSpec, d protocol.Dependencies) (transport.Binding, error) {
	s, err := upstream.NewMultiService[string](upstream.ServiceOptions{Handler: d.Handler, Logger: d.Logger})
	if err != nil {
		return transport.Binding{}, err
	}
	if err = s.UpdateUsers(r.Spec.CredentialRefs, stream.Passwords(r)); err != nil {
		return transport.Binding{}, err
	}
	return transport.Binding{Stream: &transport.StreamHandler{Serve: func(ctx context.Context, c net.Conn, src M.Socksaddr, close N.CloseHandlerFunc) error {
		return s.NewConnection(ctx, &transport.FirstRead{Conn: c, Minimum: 32}, src, close)
	}}}, nil
}
