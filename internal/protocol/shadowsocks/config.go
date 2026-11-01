// SPDX-License-Identifier: GPL-3.0-only
package shadowsocks

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/Ember-Moth/Lunaris/internal/transport"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
)

var Methods = []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"}

type Options struct {
	Method string `json:"method"`
}
type Factory struct{}

func (Factory) Capabilities() protocol.Capabilities {
	return protocol.Capabilities{Type: "shadowsocks", TCP: true, UDP: true, TCPRelay: true, UDPRelay: true, Transports: []string{"native"}}
}

func parseOptions(spec model.ListenerSpec) (Options, error) {
	var options Options
	decoder := json.NewDecoder(bytes.NewReader(spec.Options))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&options); err != nil {
		return options, errors.New("invalid Shadowsocks options")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return options, errors.New("invalid Shadowsocks options")
	}
	if !slices.Contains(Methods, options.Method) {
		return options, errors.New("method must be aes-128-gcm, aes-256-gcm or chacha20-ietf-poly1305")
	}
	return options, nil
}

func (Factory) Validate(spec model.ListenerSpec) []model.FieldError {
	var result []model.FieldError
	if _, err := parseOptions(spec); err != nil {
		result = append(result, model.FieldError{Path: "options", Code: "invalid_options", Message: err.Error()})
	}
	if len(spec.CredentialRefs) != 1 {
		result = append(result, model.FieldError{Path: "credential_refs", Code: "invalid_credentials", Message: "this Shadowsocks listener requires exactly one credential"})
	}
	return result
}

func (f Factory) Build(r protocol.ResolvedListenerSpec, d protocol.Dependencies) (transport.Binding, error) {
	s, err := f.buildServer(r, d)
	if err != nil {
		return transport.Binding{}, err
	}
	return s.binding(), nil
}
func (s *Server) binding() transport.Binding {
	return transport.Binding{Stream: &transport.StreamHandler{Serve: s.ServeStream}, Packet: &transport.PacketHandler{Serve: s.ServePacket, Close: s.ClosePacket}}
}
func (f Factory) buildServer(resolved protocol.ResolvedListenerSpec, dependencies protocol.Dependencies) (*Server, error) {
	if fields := f.Validate(resolved.Spec); len(fields) > 0 {
		return nil, errors.New(fields[0].Message)
	}
	if dependencies.Handler == nil {
		return nil, errors.New("Shadowsocks relay handler is required")
	}
	options, _ := parseOptions(resolved.Spec)
	secret := resolved.Credentials[resolved.Spec.CredentialRefs[0]]
	if len(secret) == 0 {
		return nil, errors.New("resolved Shadowsocks credential is empty")
	}
	method, err := shadowaead.New(options.Method, nil, string(secret))
	if err != nil {
		return nil, errors.New("cannot initialize Shadowsocks cipher")
	}
	limits := resolved.Limits
	if limits.MaxConnections <= 0 || limits.MaxPendingHandshakes <= 0 || limits.MaxUDPSessions <= 0 || limits.UDPQueueSize <= 0 || limits.HandshakeTimeout <= 0 {
		return nil, errors.New("invalid Shadowsocks runtime limits")
	}
	server := newServer(limits, dependencies.Handler, method)
	server.service, err = shadowaead.NewService(options.Method, nil, string(secret), int64(limits.UDPIdleTimeout.Seconds()), server)
	if err != nil {
		return nil, fmt.Errorf("initialize Shadowsocks service: invalid cipher configuration")
	}
	if options.Method == "aes-128-gcm" {
		server.saltSize = 16
	} else {
		server.saltSize = 32
	}
	return server, nil
}
