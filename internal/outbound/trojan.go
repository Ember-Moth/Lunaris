// SPDX-License-Identifier: GPL-3.0-only
package outbound

import (
	"context"
	"encoding/json"
	"errors"
	"net"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol/trojan"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type tlsOnlyOptions struct {
	TLS *TLSOptions `json:"tls,omitempty"`
}
type trojanFactory struct{}

func (trojanFactory) Capabilities() Capabilities {
	return Capabilities{Protocol: "trojan", TCP: true, UDP: true}
}
func (trojanFactory) Normalize(s model.OutboundSpec, secret []byte) (json.RawMessage, error) {
	return normalizeTLSOnly(s, secret)
}
func normalizeTLSOnly(s model.OutboundSpec, secret []byte) (json.RawMessage, error) {
	var o tlsOnlyOptions
	if err := decodeOptions(s.Options, &o); err != nil {
		return nil, err
	}
	if len(secret) == 0 {
		return nil, errors.New("outbound password credential required")
	}
	var err error
	o.TLS, err = normalizeTLS(o.TLS, s.Address, true, false)
	if err != nil {
		return nil, err
	}
	return json.Marshal(o)
}
func (trojanFactory) Build(_ context.Context, s model.OutboundSpec, secret []byte, d N.Dialer, limits model.Limits) (ProtocolClient, error) {
	var o tlsOnlyOptions
	_ = json.Unmarshal(s.Options, &o)
	carrier, err := newCarrier(s, o.TLS, d, limits)
	if err != nil {
		return nil, err
	}
	return &trojanClient{carrier: carrier, password: string(secret)}, nil
}

type trojanClient struct {
	carrier  *streamCarrier
	password string
}

func (*trojanClient) Close() error { return nil }
func (c *trojanClient) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	if network != "tcp" {
		return nil, ErrUnsupportedNetwork
	}
	raw, err := c.carrier.open(ctx)
	if err != nil {
		return nil, err
	}
	if err = handshake(ctx, raw, func() error { return trojan.WriteClientRequest(raw, c.password, dst, false) }); err != nil {
		return nil, err
	}
	return raw, nil
}
func (c *trojanClient) ListenPacket(ctx context.Context, dst M.Socksaddr) (net.PacketConn, error) {
	raw, err := c.carrier.open(ctx)
	if err != nil {
		return nil, err
	}
	if err = handshake(ctx, raw, func() error { return trojan.WriteClientRequest(raw, c.password, dst, true) }); err != nil {
		return nil, err
	}
	return trojan.NewClientPacketConn(raw), nil
}
