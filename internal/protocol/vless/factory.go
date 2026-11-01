// SPDX-License-Identifier: GPL-3.0-only
package vless

import (
	"context"
	"net"

	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/Ember-Moth/Lunaris/internal/protocol/stream"
	wire "github.com/Ember-Moth/Lunaris/internal/protocol/vless/wire"
	"github.com/Ember-Moth/Lunaris/internal/protocol/vless/wire/encryption"
	"github.com/Ember-Moth/Lunaris/internal/transport"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type Factory struct{}

func (Factory) Capabilities() protocol.Capabilities {
	return protocol.Capabilities{Type: "vless", UDPOverTCP: true, Multiplex: true, TCP: true, TCPRelay: true, UDPRelay: true, TLS: true, Transports: []string{"tcp", "ws", "httpupgrade", "reality", "xhttp"}}
}
func (Factory) Build(r protocol.ResolvedListenerSpec, d protocol.Dependencies) (transport.Binding, error) {
	o, err := parseOptions(r.Spec)
	if err != nil {
		return transport.Binding{}, err
	}
	cfg, err := decryptionConfig(r)
	if err != nil {
		return transport.Binding{}, err
	}
	s := wire.NewService[string](d.Logger, d.Handler)
	flows := make([]string, len(r.Spec.CredentialRefs))
	for i := range flows {
		flows[i] = o.Flow
	}
	if err = s.UpdateUsers(r.Spec.CredentialRefs, stream.Passwords(r), flows); err != nil {
		return transport.Binding{}, err
	}
	binding := &transport.StreamHandler{Serve: s.NewConnection}
	if cfg != nil {
		var instance *encryption.ServerInstance
		// Defer cache ownership until Start, so carrier construction failure leaks no worker.
		binding.Start = func() error {
			var err error
			instance, err = cfg.NewInstanceWithLimit(min(4096, r.Limits.MaxConnections+r.Limits.MaxUDPSessions))
			return err
		}
		binding.Close = func() error {
			if instance != nil {
				return instance.Close()
			}
			return nil
		}
		binding.Serve = func(ctx context.Context, c net.Conn, src M.Socksaddr, close N.CloseHandlerFunc) error {
			handshake, cancel := context.WithTimeout(ctx, r.Limits.HandshakeTimeout)
			encrypted, err := instance.HandshakeContext(handshake, c, nil)
			cancel()
			if err != nil {
				return err
			}
			return s.NewConnection(ctx, encrypted, src, close)
		}
	}
	return transport.Binding{Stream: binding}, nil
}
