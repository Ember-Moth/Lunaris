// SPDX-License-Identifier: GPL-3.0-only
package hysteria2

import (
	"context"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/Ember-Moth/Lunaris/internal/protocol/stream"
	"github.com/Ember-Moth/Lunaris/internal/transport"
	qtls "github.com/sagernet/sing-quic"
	upstream "github.com/sagernet/sing-quic/hysteria2"
	aTLS "github.com/sagernet/sing/common/tls"
)

type Factory struct{}

func (Factory) Capabilities() protocol.Capabilities {
	return protocol.Capabilities{Type: "hysteria2", UDP: true, TCPRelay: true, UDPRelay: true, TLS: true, TLSRequired: true, Transports: []string{"quic"}}
}
func (Factory) Validate(s model.ListenerSpec) []model.FieldError { return stream.Validate(s) }
func (Factory) ValidateAssets(r protocol.ResolvedListenerSpec) error {
	return stream.ValidateAssets(r, false)
}
func (Factory) Build(r protocol.ResolvedListenerSpec, d protocol.Dependencies) (transport.Binding, error) {
	return transport.Binding{QUIC: &transport.QUICHandler{ALPN: []string{"h3"}, ReservedStreams: 1, NewService: func(ctx context.Context, tls aTLS.ServerConfig, options qtls.QUICOptions) (transport.QUICService, error) {
		s, err := upstream.NewService[string](upstream.ServiceOptions{Context: ctx, Logger: d.Logger, TLSConfig: tls, QUICOptions: options, IgnoreClientBandwidth: true, UDPTimeout: r.Limits.UDPIdleTimeout, Handler: d.Handler})
		if err != nil {
			return nil, err
		}
		s.UpdateUsers(r.Spec.CredentialRefs, stream.Passwords(r))
		return s, nil
	}}}, nil
}
