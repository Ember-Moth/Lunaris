// SPDX-License-Identifier: GPL-3.0-only
package naive

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/Ember-Moth/Lunaris/internal/transport"
	"github.com/sagernet/sing/common/auth"
)

type Factory struct{}
type User struct {
	Username      string `json:"username"`
	CredentialRef string `json:"credential_ref"`
}
type Options struct {
	Users []User `json:"users"`
}

func (Factory) Capabilities() protocol.Capabilities {
	return protocol.Capabilities{Type: "naive", TCP: true, UDP: true, TCPRelay: true, UDPRelay: true, TLS: true, TLSRequired: true, UDPOverTCP: true, UDPOverTCPRequired: true, Transports: []string{"http", "quic"}}
}
func parse(s model.ListenerSpec) (Options, error) {
	var o Options
	d := json.NewDecoder(bytes.NewReader(s.Options))
	d.DisallowUnknownFields()
	if err := d.Decode(&o); err != nil {
		return o, errors.New("invalid Naive options")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return o, errors.New("trailing Naive options")
	}
	if len(o.Users) == 0 || len(o.Users) != len(s.CredentialRefs) {
		return o, errors.New("Naive users must map every credential reference exactly once")
	}
	users, refs := map[string]bool{}, map[string]bool{}
	for _, u := range o.Users {
		if u.Username == "" || len(u.Username) > 256 || strings.ContainsAny(u.Username, ":\r\n\x00") || users[u.Username] || refs[u.CredentialRef] || !slices.Contains(s.CredentialRefs, u.CredentialRef) {
			return o, errors.New("invalid or duplicate Naive user mapping")
		}
		users[u.Username] = true
		refs[u.CredentialRef] = true
	}
	return o, nil
}
func (Factory) Validate(s model.ListenerSpec) []model.FieldError {
	if _, err := parse(s); err != nil {
		return []model.FieldError{{Path: "options", Code: "invalid_options", Message: err.Error()}}
	}
	return nil
}
func (Factory) ValidateAssets(r protocol.ResolvedListenerSpec) error {
	for _, ref := range r.Spec.CredentialRefs {
		if len(r.Credentials[ref]) == 0 {
			return errors.New("empty Naive credential")
		}
	}
	return nil
}
func (f Factory) Build(r protocol.ResolvedListenerSpec, d protocol.Dependencies) (transport.Binding, error) {
	o, err := parse(r.Spec)
	if err != nil {
		return transport.Binding{}, err
	}
	if err = f.ValidateAssets(r); err != nil {
		return transport.Binding{}, err
	}
	if d.Handler == nil {
		return transport.Binding{}, errors.New("Naive relay handler required")
	}
	users := make([]auth.User, len(o.Users))
	for i, u := range o.Users {
		users[i] = auth.User{Username: u.Username, Password: string(r.Credentials[u.CredentialRef])}
	}
	return transport.Binding{HTTP: &handler{auth: auth.NewAuthenticator(users), next: d.Handler, timeout: r.Limits.HandshakeTimeout}}, nil
}
