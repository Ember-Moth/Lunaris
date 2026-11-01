// SPDX-License-Identifier: GPL-3.0-only
package quic

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"slices"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/gofrs/uuid/v5"
)

type Factory struct{ Type model.ProtocolType }
type User struct {
	UUID          string `json:"uuid"`
	CredentialRef string `json:"credential_ref"`
}
type Options struct {
	Users             []User `json:"users,omitempty"`
	CongestionControl string `json:"congestion_control,omitempty"`
}

func (f Factory) Capabilities() protocol.Capabilities {
	return protocol.Capabilities{Type: f.Type, UDP: true, TCPRelay: true, UDPRelay: true, Transports: []string{"quic"}}
}
func (f Factory) parse(s model.ListenerSpec) (Options, error) {
	var o Options
	d := json.NewDecoder(bytes.NewReader(s.Options))
	d.DisallowUnknownFields()
	if err := d.Decode(&o); err != nil {
		return o, errors.New("invalid QUIC protocol options")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return o, errors.New("trailing protocol options")
	}
	if f.Type == "hysteria2" {
		if len(o.Users) > 0 || o.CongestionControl != "" {
			return o, errors.New("Hysteria2 uses credential_refs and automatic bandwidth")
		}
		return o, nil
	}
	if !slices.Contains([]string{"", "cubic", "new_reno", "bbr"}, o.CongestionControl) {
		return o, errors.New("invalid TUIC congestion control")
	}
	if len(o.Users) != len(s.CredentialRefs) {
		return o, errors.New("TUIC users must map every credential reference exactly once")
	}
	ids, refs := map[uuid.UUID]bool{}, map[string]bool{}
	for _, u := range o.Users {
		id, err := uuid.FromString(u.UUID)
		if err != nil || id == uuid.Nil || ids[id] || refs[u.CredentialRef] || !slices.Contains(s.CredentialRefs, u.CredentialRef) {
			return o, errors.New("invalid or duplicate TUIC user mapping")
		}
		ids[id] = true
		refs[u.CredentialRef] = true
	}
	return o, nil
}
func (f Factory) Validate(s model.ListenerSpec) []model.FieldError {
	fail := func(path, msg string) []model.FieldError {
		return []model.FieldError{{Path: path, Code: "invalid", Message: msg}}
	}
	if _, err := f.parse(s); err != nil {
		return fail("options", err.Error())
	}
	if len(s.CredentialRefs) == 0 {
		return fail("credential_refs", "at least one credential is required")
	}
	if s.CertificateRef == "" {
		return fail("certificate_ref", "QUIC requires a TLS certificate")
	}
	if (s.Transport.Type != "" && s.Transport.Type != "quic") || s.Transport.Path != "" || s.Transport.Host != "" {
		return fail("transport", "this protocol requires native QUIC")
	}
	return nil
}
func (f Factory) ValidateAssets(r protocol.ResolvedListenerSpec) error {
	seen := map[string]bool{}
	for _, ref := range r.Spec.CredentialRefs {
		p := string(r.Credentials[ref])
		if p == "" {
			return errors.New("empty protocol credential")
		}
		if seen[p] && f.Type == "hysteria2" {
			return errors.New("duplicate Hysteria2 password")
		}
		seen[p] = true
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
	cert, err := tls.X509KeyPair(r.Certificate, r.PrivateKey)
	if err != nil {
		return nil, errors.New("invalid QUIC TLS key pair")
	}
	opts, _ := f.parse(r.Spec)
	return newServer(r, d, opts, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}}), nil
}
