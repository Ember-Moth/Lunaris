// SPDX-License-Identifier: GPL-3.0-only
package shadowsocks

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/Ember-Moth/Lunaris/internal/transport"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
)

var Methods = []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"}

type Options struct {
	Method       string `json:"method"`
	ServerKeyRef string `json:"server_key_ref,omitempty"`
}
type Factory struct{}

func (Factory) Capabilities() protocol.Capabilities {
	return protocol.Capabilities{Type: "shadowsocks", UDPOverTCP: true, Multiplex: true, TCP: true, UDP: true, TCPRelay: true, UDPRelay: true, TLS: true, Transports: []string{"native", "obfs", "v2ray-plugin", "gost-plugin", "shadow-tls", "restls", "kcptun"}}
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
	if !slices.Contains(Methods, options.Method) && !slices.Contains(shadowaead_2022.List, options.Method) {
		return options, errors.New("unsupported Shadowsocks AEAD or 2022 method")
	}
	if options.ServerKeyRef != "" && options.Method != "2022-blake3-aes-128-gcm" && options.Method != "2022-blake3-aes-256-gcm" {
		return options, errors.New("server_key_ref requires a Shadowsocks 2022 AES-GCM method")
	}
	return options, nil
}

func (Factory) Validate(spec model.ListenerSpec) []model.FieldError {
	var result []model.FieldError
	if _, err := parseOptions(spec); err != nil {
		result = append(result, model.FieldError{Path: "options", Code: "invalid_options", Message: err.Error()})
	}
	options, _ := parseOptions(spec)
	if options.ServerKeyRef != "" && slices.Contains(spec.CredentialRefs, options.ServerKeyRef) {
		result = append(result, model.FieldError{Path: "options.server_key_ref", Code: "invalid_credentials", Message: "server key must be separate from user keys"})
	}
	if len(spec.CredentialRefs) == 0 || (slices.Contains(shadowaead_2022.List, options.Method) && options.ServerKeyRef == "" && len(spec.CredentialRefs) != 1) {
		result = append(result, model.FieldError{Path: "credential_refs", Code: "invalid_credentials", Message: "at least one credential is required; Shadowsocks 2022 without a server key requires exactly one"})
	}
	return result
}

func (f Factory) Build(r protocol.ResolvedListenerSpec, d protocol.Dependencies) (transport.Binding, error) {
	options, err := parseOptions(r.Spec)
	if err != nil {
		return transport.Binding{}, err
	}
	if slices.Contains(shadowaead_2022.List, options.Method) {
		return f.build2022(r, d, options)
	}
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
	if err := f.ValidateAssets(resolved); err != nil {
		return nil, err
	}
	limits := resolved.Limits
	if limits.MaxConnections <= 0 || limits.MaxPendingHandshakes <= 0 || limits.MaxUDPSessions <= 0 || limits.UDPQueueSize <= 0 || limits.HandshakeTimeout <= 0 {
		return nil, errors.New("invalid Shadowsocks runtime limits")
	}
	server := newServer(limits, dependencies.Handler, nil)
	if options.Method == "aes-128-gcm" {
		server.saltSize = 16
	} else {
		server.saltSize = 32
	}
	if err := server.initUsers(resolved, options.Method); err != nil {
		return nil, err
	}
	return server, nil
}

func (Factory) CredentialRefs(spec model.ListenerSpec) []string {
	options, err := parseOptions(spec)
	if err != nil || options.ServerKeyRef == "" {
		return nil
	}
	return []string{options.ServerKeyRef}
}
func (Factory) ValidateAssets(r protocol.ResolvedListenerSpec) error {
	options, err := parseOptions(r.Spec)
	if err != nil {
		return err
	}
	refs := slices.Clone(r.Spec.CredentialRefs)
	if options.ServerKeyRef != "" {
		refs = append(refs, options.ServerKeyRef)
	}
	seen := map[string]bool{}
	for _, ref := range refs {
		secret := r.Credentials[ref]
		if len(secret) == 0 {
			return errors.New("empty Shadowsocks credential")
		}
		if !slices.Contains(shadowaead_2022.List, options.Method) {
			if seen[string(secret)] {
				return errors.New("duplicate Shadowsocks credentials")
			}
			seen[string(secret)] = true
		}
		if slices.Contains(shadowaead_2022.List, options.Method) {
			size := 32
			if options.Method == "2022-blake3-aes-128-gcm" {
				size = 16
			}
			key, err := base64.StdEncoding.Strict().DecodeString(string(secret))
			if err != nil || len(key) != size || base64.StdEncoding.EncodeToString(key) != string(secret) {
				return fmt.Errorf("Shadowsocks 2022 credentials must be canonical base64 of exactly %d bytes", size)
			}
			if seen[string(key)] {
				return errors.New("duplicate Shadowsocks 2022 keys")
			}
			seen[string(key)] = true
		}
	}
	return nil
}
