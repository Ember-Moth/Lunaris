// SPDX-License-Identifier: GPL-3.0-only
package mieru

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"slices"
	"strings"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/Ember-Moth/Lunaris/internal/protocol/mieru/native"
	"github.com/Ember-Moth/Lunaris/internal/transport"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type Factory struct{}
type User struct {
	Username      string `json:"username"`
	CredentialRef string `json:"credential_ref"`
}
type Options struct {
	Users               []User `json:"users"`
	TrafficPattern      string `json:"traffic_pattern,omitempty"`
	UserHintIsMandatory bool   `json:"user_hint_is_mandatory,omitempty"`
	MTU                 int    `json:"mtu,omitempty"`
}

func (Factory) Capabilities() protocol.Capabilities {
	return protocol.Capabilities{Type: "mieru", TCP: true, UDP: true, TCPRelay: true, UDPRelay: true, Transports: []string{"native"}}
}
func parse(s model.ListenerSpec) (Options, error) {
	var o Options
	decoder := json.NewDecoder(bytes.NewReader(s.Options))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&o); err != nil {
		return o, errors.New("invalid Mieru options")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return o, errors.New("trailing Mieru options")
	}
	if len(o.Users) == 0 || len(o.Users) != len(s.CredentialRefs) {
		return o, errors.New("Mieru users must map every credential reference")
	}
	names, refs := map[string]bool{}, map[string]bool{}
	for _, u := range o.Users {
		if u.Username == "" || len(u.Username) > 256 || strings.ContainsAny(u.Username, "\r\n\x00") || names[u.Username] || refs[u.CredentialRef] || !slices.Contains(s.CredentialRefs, u.CredentialRef) {
			return o, errors.New("invalid or duplicate Mieru user mapping")
		}
		names[u.Username] = true
		refs[u.CredentialRef] = true
	}
	if len(o.TrafficPattern) > 65536 {
		return o, errors.New("Mieru traffic pattern exceeds 64 KiB")
	}
	if err := native.ValidateTrafficPattern(o.TrafficPattern); err != nil {
		return o, errors.New("invalid Mieru traffic pattern")
	}
	if o.MTU != 0 && (o.MTU < 576 || o.MTU > 9000) {
		return o, errors.New("Mieru MTU must be 576..9000")
	}
	return o, nil
}
func (Factory) Validate(s model.ListenerSpec) []model.FieldError {
	if _, err := parse(s); err != nil {
		return []model.FieldError{{Path: "options", Code: "invalid", Message: err.Error()}}
	}
	return nil
}
func (Factory) ValidateAssets(r protocol.ResolvedListenerSpec) error {
	for _, ref := range r.Spec.CredentialRefs {
		if len(r.Credentials[ref]) == 0 {
			return errors.New("empty Mieru credential")
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
	users := make([]native.User, len(o.Users))
	for i, u := range o.Users {
		users[i] = native.User{Name: u.Username, Password: string(r.Credentials[u.CredentialRef])}
	}
	s, err := native.NewServer(native.ServerOptions{Context: context.Background(), ListenAddress: "managed", Transport: native.TransportTCP, MTU: o.MTU, Users: users, TrafficPattern: o.TrafficPattern, UserHintIsMandatory: o.UserHintIsMandatory, TCPHandler: d.Handler, UDPHandler: d.Handler, Logger: d.Logger, MaxSessions: r.Limits.MaxConnections + r.Limits.MaxUDPSessions, MaxPending: r.Limits.MaxPendingHandshakes, OnAuthenticated: transport.ReleaseHandshake, QueueSize: r.Limits.UDPQueueSize, HandshakeTimeout: r.Limits.HandshakeTimeout, IdleTimeout: r.Limits.UDPIdleTimeout, WriteTimeout: r.Limits.DialTimeout})
	if err != nil {
		return transport.Binding{}, err
	}
	return transport.Binding{Stream: &transport.StreamHandler{Start: s.StartManaged, Close: s.Close, Serve: func(ctx context.Context, c net.Conn, _ M.Socksaddr, close N.CloseHandlerFunc) error {
		err := s.ServeConnection(ctx, c)
		if close != nil {
			close(err)
		}
		return err
	}}, Packet: &transport.PacketHandler{Serve: s.ServePacket, Close: func(context.Context) error { return s.Close() }}}, nil
}
