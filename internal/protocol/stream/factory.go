// SPDX-License-Identifier: GPL-3.0-only
package stream

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net/url"
	"strings"

	"context"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/Ember-Moth/Lunaris/internal/protocol/trojan"
	"github.com/Ember-Moth/Lunaris/internal/transport"
	"github.com/gofrs/uuid/v5"
	anytls "github.com/sagernet/sing-anytls"
	vmess "github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"net"
)

type Factory struct{ Type model.ProtocolType }

func (f Factory) Capabilities() protocol.Capabilities {
	ts := []string{"tcp", "ws", "httpupgrade"}
	if f.Type == "anytls" {
		ts = []string{"tcp"}
	}
	return protocol.Capabilities{Type: f.Type, TCP: true, TCPRelay: true, UDPRelay: f.Type != "anytls", Transports: ts}
}
func (f Factory) Validate(s model.ListenerSpec) []model.FieldError {
	fail := func(path, msg string) []model.FieldError {
		return []model.FieldError{{Path: path, Code: "invalid", Message: msg}}
	}
	raw := bytes.TrimSpace(s.Options)
	if len(raw) != 0 && !bytes.Equal(raw, []byte("{}")) && !bytes.Equal(raw, []byte("null")) {
		return fail("options", "this protocol has no configurable options in this version")
	}
	if len(s.CredentialRefs) == 0 {
		return fail("credential_refs", "at least one credential is required")
	}
	t := s.Transport
	switch t.Type {
	case "", "tcp":
		if t.Path != "" || t.Host != "" {
			return fail("transport", "TCP does not accept path or host")
		}
	case "ws", "httpupgrade":
		if f.Type == "anytls" {
			return fail("transport", "AnyTLS requires native TLS over TCP")
		}
		u, err := url.ParseRequestURI(t.Path)
		if err != nil || !strings.HasPrefix(t.Path, "/") || strings.HasPrefix(t.Path, "//") || u.RawQuery != "" || u.Fragment != "" || u.EscapedPath() != t.Path || len(t.Path) > 1024 {
			return fail("transport.path", "an absolute path without query or fragment is required")
		}
		if strings.ContainsAny(t.Host, "\r\n /\\") {
			return fail("transport.host", "invalid HTTP host")
		}
	default:
		return fail("transport.type", "supported transports: tcp, ws, httpupgrade")
	}
	if (f.Type == "anytls" || f.Type == "trojan") && s.CertificateRef == "" {
		return fail("certificate_ref", "TLS certificate is required")
	}
	return nil
}
func (f Factory) ValidateAssets(r protocol.ResolvedListenerSpec) error {
	seen := make(map[string]bool)
	for _, ref := range r.Spec.CredentialRefs {
		secret := string(r.Credentials[ref])
		if secret == "" {
			return errors.New("empty protocol credential")
		}
		if f.Type == "vless" || f.Type == "vmess" {
			u, err := uuid.FromString(secret)
			if err != nil || u == uuid.Nil {
				return errors.New("VLESS and VMess credentials must be nonzero UUIDs")
			}
			secret = u.String()
		}
		if seen[secret] {
			return errors.New("duplicate protocol credential")
		}
		seen[secret] = true
	}
	return nil
}
func (f Factory) Build(r protocol.ResolvedListenerSpec, d protocol.Dependencies) (protocol.Instance, error) {
	if err := protocol.ValidateLimits(r.Limits); err != nil {
		return nil, err
	}
	if fields := f.Validate(r.Spec); len(fields) > 0 {
		return nil, errors.New(fields[0].Message)
	}
	if err := f.ValidateAssets(r); err != nil {
		return nil, err
	}
	if d.Handler == nil {
		return nil, errors.New("relay handler required")
	}
	if d.Logger == nil {
		d.Logger = logger.NOP()
	}
	server := transport.NewStream(r.Spec, r.Limits)
	if r.Spec.CertificateRef != "" {
		cert, err := tls.X509KeyPair(r.Certificate, r.PrivateKey)
		if err != nil {
			return nil, errors.New("invalid TLS key pair")
		}
		server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		if r.Spec.Transport.Type == "ws" || r.Spec.Transport.Type == "httpupgrade" {
			server.TLS.NextProtos = []string{"http/1.1"}
		}
	}
	h := transport.Bridge{Handler: d.Handler}
	users, passwords := r.Spec.CredentialRefs, make([]string, len(r.Spec.CredentialRefs))
	for i, id := range users {
		passwords[i] = string(r.Credentials[id])
	}
	switch f.Type {
	case "vless":
		s := vless.NewService[string](d.Logger, h)
		s.UpdateUsers(users, passwords, make([]string, len(users)))
		server.Serve = s.NewConnection
	case "vmess":
		// Read the authenticated header across fragmented TCP/WS reads. AEAD
		// authentication and replay checks remain in the upstream service.
		s := vmess.NewService[string](h, vmess.ServiceWithDisableHeaderProtection())
		if err := s.UpdateUsers(users, passwords, make([]int, len(users))); err != nil {
			return nil, errors.New("invalid VMess users")
		}
		server.Serve = s.NewConnection
		server.OnStart = s.Start
		server.OnClose = s.Close
	case "trojan":
		s := trojan.New(users, passwords, h)
		server.Serve = s.NewConnection
	case "anytls":
		s, err := anytls.NewMultiService[string](anytls.ServiceOptions{Handler: h, Logger: d.Logger})
		if err != nil {
			return nil, err
		}
		if err = s.UpdateUsers(users, passwords); err != nil {
			return nil, err
		}
		server.Serve = func(ctx context.Context, c net.Conn, src M.Socksaddr, close N.CloseHandlerFunc) error {
			return s.NewConnection(ctx, &transport.FirstRead{Conn: c, Minimum: 32}, src, close)
		}
	default:
		return nil, errors.New("unknown stream protocol")
	}
	return server, nil
}
