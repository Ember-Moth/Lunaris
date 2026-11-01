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
	"github.com/sagernet/sing-shadowsocks/shadowaead"
)

var Methods = []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"}

type Options struct {
	Method string `json:"method"`
}
type Factory struct{}

func (Factory) Capabilities() protocol.Capabilities {
	return protocol.Capabilities{Type: "shadowsocks", TCP: true, UDP: true, TCPRelay: true, UDPRelay: true}
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
	if spec.Transport != (model.Transport{}) {
		result = append(result, model.FieldError{Path: "transport", Code: "unsupported", Message: "Shadowsocks uses native TCP/UDP only"})
	}
	if _, err := parseOptions(spec); err != nil {
		result = append(result, model.FieldError{Path: "options", Code: "invalid_options", Message: err.Error()})
	}
	if len(spec.CredentialRefs) != 1 {
		result = append(result, model.FieldError{Path: "credential_refs", Code: "invalid_credentials", Message: "this Shadowsocks listener requires exactly one credential"})
	}
	if spec.CertificateRef != "" {
		result = append(result, model.FieldError{Path: "certificate_ref", Code: "unsupported", Message: "TLS transport is not supported for this listener"})
	}
	return result
}

func (f Factory) Build(resolved protocol.ResolvedListenerSpec, dependencies protocol.Dependencies) (protocol.Instance, error) {
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
	server := newServer(resolved.Spec, limits, dependencies.Handler, method)
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
