// SPDX-License-Identifier: GPL-3.0-only
package shadowsocksr

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	wire "github.com/Ember-Moth/Lunaris/internal/protocol/shadowsocksr/wire"
	"github.com/Ember-Moth/Lunaris/internal/transport"
)

type Factory struct{}
type User struct {
	ID            uint32 `json:"id"`
	CredentialRef string `json:"credential_ref"`
}
type Options struct {
	Method        string `json:"method"`
	Protocol      string `json:"protocol"`
	ProtocolParam string `json:"protocol_param,omitempty"`
	Obfs          string `json:"obfs,omitempty"`
	ObfsParam     string `json:"obfs_param,omitempty"`
	ServerKeyRef  string `json:"server_key_ref,omitempty"`
	Users         []User `json:"users,omitempty"`
}

func (Factory) Capabilities() protocol.Capabilities {
	return protocol.Capabilities{Type: "shadowsocksr", TCP: true, UDP: true, TCPRelay: true, UDPRelay: true, Transports: []string{"native"}}
}
func parse(s model.ListenerSpec) (Options, error) {
	var o Options
	d := json.NewDecoder(bytes.NewReader(s.Options))
	d.DisallowUnknownFields()
	if err := d.Decode(&o); err != nil {
		return o, errors.New("invalid ShadowsocksR options")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return o, errors.New("trailing ShadowsocksR options")
	}
	o.Method = strings.ToLower(strings.TrimSpace(o.Method))
	o.Protocol = strings.ToLower(strings.TrimSpace(o.Protocol))
	o.Obfs = strings.ToLower(strings.TrimSpace(o.Obfs))
	if o.Obfs == "" {
		o.Obfs = "plain"
	}
	meta, ok := wire.ProtocolInfo(o.Protocol)
	if !ok {
		return o, errors.New("unsupported ShadowsocksR protocol")
	}
	if len(s.CredentialRefs) == 0 {
		return o, errors.New("ShadowsocksR credentials required")
	}
	if meta.SingleUser {
		if len(s.CredentialRefs) != 1 || len(o.Users) != 0 {
			return o, errors.New("this ShadowsocksR protocol requires one credential and no users mapping")
		}
		o.Users = []User{{ID: 1, CredentialRef: s.CredentialRefs[0]}}
	} else {
		if len(o.Users) != len(s.CredentialRefs) {
			return o, errors.New("ShadowsocksR users must map every credential reference")
		}
		ids, refs := map[uint32]bool{}, map[string]bool{}
		for _, u := range o.Users {
			if u.ID == 0 || ids[u.ID] || refs[u.CredentialRef] || !slices.Contains(s.CredentialRefs, u.CredentialRef) {
				return o, errors.New("invalid or duplicate ShadowsocksR user mapping")
			}
			ids[u.ID] = true
			refs[u.CredentialRef] = true
		}
	}
	if len(s.CredentialRefs) > 1 && o.ServerKeyRef == "" {
		return o, errors.New("multi-user ShadowsocksR requires server_key_ref")
	}
	if o.ServerKeyRef != "" && slices.Contains(s.CredentialRefs, o.ServerKeyRef) {
		return o, errors.New("server key must be separate from user credentials")
	}
	if len(s.Network) == 1 && s.Network[0] == "udp" && o.Obfs != "plain" {
		return o, errors.New("ShadowsocksR obfs only applies to TCP")
	}
	if len(o.ProtocolParam) > 4096 || len(o.ObfsParam) > 4096 {
		return o, errors.New("ShadowsocksR parameter exceeds 4096 bytes")
	}
	if _, err := wire.NewServer(wire.ServerConfig{Method: o.Method, Password: "configuration-probe", Protocol: o.Protocol, ProtocolParam: o.ProtocolParam, Obfs: o.Obfs, ObfsParam: o.ObfsParam, Port: 1}, map[[4]byte]string{{1, 0, 0, 0}: "probe"}); err != nil {
		return o, errors.New("unsupported ShadowsocksR cipher, protocol or obfs settings")
	}
	return o, nil
}
func (Factory) Validate(s model.ListenerSpec) []model.FieldError {
	if _, err := parse(s); err != nil {
		return []model.FieldError{{Path: "options", Code: "invalid", Message: err.Error()}}
	}
	return nil
}
func (Factory) CredentialRefs(s model.ListenerSpec) []string {
	o, err := parse(s)
	if err != nil || o.ServerKeyRef == "" {
		return nil
	}
	return []string{o.ServerKeyRef}
}
func (Factory) ValidateAssets(r protocol.ResolvedListenerSpec) error {
	o, err := parse(r.Spec)
	if err != nil {
		return err
	}
	for _, ref := range r.Spec.CredentialRefs {
		if len(r.Credentials[ref]) == 0 {
			return errors.New("empty ShadowsocksR user credential")
		}
	}
	if o.ServerKeyRef != "" && len(r.Credentials[o.ServerKeyRef]) == 0 {
		return errors.New("empty ShadowsocksR server key")
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
		return transport.Binding{}, errors.New("ShadowsocksR handler required")
	}
	users := map[[4]byte]string{}
	identities := map[[4]byte]string{}
	for _, u := range o.Users {
		var id [4]byte
		binary.LittleEndian.PutUint32(id[:], u.ID)
		users[id] = string(r.Credentials[u.CredentialRef])
		identities[id] = u.CredentialRef
	}
	ref := o.ServerKeyRef
	if ref == "" {
		ref = r.Spec.CredentialRefs[0]
	}
	service, err := wire.NewServer(wire.ServerConfig{Method: o.Method, Password: string(r.Credentials[ref]), Protocol: o.Protocol, ProtocolParam: o.ProtocolParam, Obfs: o.Obfs, ObfsParam: o.ObfsParam, Host: r.Spec.Address, Port: max(1, int(r.Spec.Port)), ReplayState: wire.NewReplayStateWithCapacity(nil, 65536)}, users)
	if err != nil {
		return transport.Binding{}, err
	}
	codec, err := service.NewPacketCodec()
	if err != nil {
		return transport.Binding{}, err
	}
	s := &server{service: service, codec: codec, identities: identities, limits: r.Limits, handler: d.Handler, sessions: make(map[packetKey]*packetConn), done: make(chan struct{})}
	return transport.Binding{Stream: &transport.StreamHandler{Serve: s.serveStream}, Packet: &transport.PacketHandler{Serve: s.servePacket, Close: s.closePacket}}, nil
}
