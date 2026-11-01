// SPDX-License-Identifier: GPL-3.0-only
package tuic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/Ember-Moth/Lunaris/internal/transport"
	"github.com/gofrs/uuid/v5"
	qtls "github.com/sagernet/sing-quic"
	upstream "github.com/sagernet/sing-quic/tuic"
	aTLS "github.com/sagernet/sing/common/tls"
)

type Factory struct{}
type User struct {
	UUID          string `json:"uuid"`
	CredentialRef string `json:"credential_ref"`
}
type Options struct {
	Users             []User `json:"users,omitempty"`
	CongestionControl string `json:"congestion_control,omitempty"`
}

func (f Factory) Capabilities() protocol.Capabilities {
	return protocol.Capabilities{Type: "tuic", UDP: true, TCPRelay: true, UDPRelay: true, TLS: true, TLSRequired: true, Transports: []string{"quic"}}
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
	return nil
}
func (Factory) ValidateAssets(r protocol.ResolvedListenerSpec) error {
	for _, ref := range r.Spec.CredentialRefs {
		if len(r.Credentials[ref]) == 0 {
			return errors.New("empty TUIC credential")
		}
	}
	return nil
}
func (f Factory) Build(r protocol.ResolvedListenerSpec, d protocol.Dependencies) (transport.Binding, error) {
	opts, err := f.parse(r.Spec)
	if err != nil {
		return transport.Binding{}, err
	}
	users := make([]string, len(opts.Users))
	ids := make([][16]byte, len(users))
	passwords := make([]string, len(users))
	for i, u := range opts.Users {
		users[i] = u.CredentialRef
		ids[i] = [16]byte(uuid.FromStringOrNil(u.UUID))
		passwords[i] = string(r.Credentials[u.CredentialRef])
	}
	return transport.Binding{QUIC: &transport.QUICHandler{ALPN: []string{"h3"}, NewService: func(ctx context.Context, tls aTLS.ServerConfig, options qtls.QUICOptions) (transport.QUICService, error) {
		s, err := upstream.NewService[string](upstream.ServiceOptions{Context: ctx, Logger: d.Logger, TLSConfig: tls, QUICOptions: options, CongestionControl: opts.CongestionControl, AuthTimeout: r.Limits.HandshakeTimeout, UDPTimeout: r.Limits.UDPIdleTimeout, Handler: d.Handler})
		if err != nil {
			return nil, err
		}
		s.UpdateUsers(users, ids, passwords)
		return s, nil
	}}}, nil
}
