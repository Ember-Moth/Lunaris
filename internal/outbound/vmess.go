// SPDX-License-Identifier: GPL-3.0-only
package outbound

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"slices"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/gofrs/uuid/v5"
	vmess "github.com/sagernet/sing-vmess"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type vmessOptions struct {
	Cipher string      `json:"cipher,omitempty"`
	TLS    *TLSOptions `json:"tls,omitempty"`
}

func validUUID(secret []byte) bool {
	id, err := uuid.FromString(string(secret))
	return err == nil && id != uuid.Nil
}

type vmessFactory struct{}

func (vmessFactory) Capabilities() Capabilities {
	return Capabilities{Protocol: "vmess", TCP: true, UDP: true}
}
func (vmessFactory) Normalize(s model.OutboundSpec, secret []byte) (json.RawMessage, error) {
	var o vmessOptions
	if err := decodeOptions(s.Options, &o); err != nil {
		return nil, err
	}
	if !validUUID(secret) {
		return nil, errors.New("VMess requires a UUID credential")
	}
	if o.Cipher == "" {
		o.Cipher = "auto"
	}
	if !slices.Contains([]string{"auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"}, o.Cipher) {
		return nil, errors.New("unsupported VMess AEAD cipher")
	}
	var err error
	o.TLS, err = normalizeTLS(o.TLS, s.Address, false, false)
	if err != nil {
		return nil, err
	}
	return json.Marshal(o)
}
func (vmessFactory) Build(_ context.Context, s model.OutboundSpec, secret []byte, d N.Dialer, limits model.Limits) (ProtocolClient, error) {
	var o vmessOptions
	_ = json.Unmarshal(s.Options, &o)
	carrier, err := newCarrier(s, o.TLS, d, limits)
	if err != nil {
		return nil, err
	}
	protocol, err := vmess.NewClient(string(secret), o.Cipher, 0)
	if err != nil {
		return nil, errors.New("invalid VMess client")
	}
	return &vmessClient{carrier: carrier, protocol: protocol}, nil
}

type vmessClient struct {
	carrier  *streamCarrier
	protocol *vmess.Client
}

func (*vmessClient) Close() error { return nil }
func (c *vmessClient) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	if network != "tcp" {
		return nil, ErrUnsupportedNetwork
	}
	raw, err := c.carrier.open(ctx)
	if err != nil {
		return nil, err
	}
	var conn net.Conn
	err = handshake(ctx, raw, func() error { var err error; conn, err = c.protocol.DialConn(raw, dst); return err })
	return conn, err
}
func (c *vmessClient) ListenPacket(ctx context.Context, dst M.Socksaddr) (net.PacketConn, error) {
	raw, err := c.carrier.open(ctx)
	if err != nil {
		return nil, err
	}
	var conn net.PacketConn
	err = handshake(ctx, raw, func() error { var err error; conn, err = c.protocol.DialXUDPPacketConn(raw, dst); return err })
	return conn, err
}
