// SPDX-License-Identifier: GPL-3.0-only
package outbound

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol/vless/wire"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type vlessOptions struct {
	Flow string      `json:"flow,omitempty"`
	TLS  *TLSOptions `json:"tls,omitempty"`
}
type vlessFactory struct{}

func (vlessFactory) Capabilities() Capabilities {
	return Capabilities{Protocol: "vless", TCP: true, UDP: true}
}
func (vlessFactory) Normalize(s model.OutboundSpec, secret []byte) (json.RawMessage, error) {
	var o vlessOptions
	if err := decodeOptions(s.Options, &o); err != nil {
		return nil, err
	}
	if !validUUID(secret) {
		return nil, errors.New("VLESS requires a UUID credential")
	}
	if o.Flow != "" && o.Flow != "xtls-rprx-vision" {
		return nil, errors.New("unsupported VLESS flow")
	}
	var err error
	o.TLS, err = normalizeTLS(o.TLS, s.Address, false, false)
	if err != nil {
		return nil, err
	}
	if o.Flow != "" && o.TLS == nil {
		return nil, errors.New("Vision requires TLS")
	}
	return json.Marshal(o)
}
func (vlessFactory) Build(_ context.Context, s model.OutboundSpec, secret []byte, d N.Dialer, limits model.Limits) (ProtocolClient, error) {
	var o vlessOptions
	_ = json.Unmarshal(s.Options, &o)
	carrier, err := newCarrier(s, o.TLS, d, limits)
	if err != nil {
		return nil, err
	}
	if o.Flow != "" {
		carrier.tls.MinVersion = tls.VersionTLS13
	}
	protocol, err := vless.NewClient(string(secret), o.Flow, logger.NOP())
	if err != nil {
		return nil, errors.New("invalid VLESS client")
	}
	return &vlessClient{carrier: carrier, protocol: protocol}, nil
}

type vlessClient struct {
	carrier  *streamCarrier
	protocol *vless.Client
}

func (*vlessClient) Close() error { return nil }
func (c *vlessClient) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
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
func (c *vlessClient) ListenPacket(ctx context.Context, dst M.Socksaddr) (net.PacketConn, error) {
	raw, err := c.carrier.open(ctx)
	if err != nil {
		return nil, err
	}
	var conn net.PacketConn
	err = handshake(ctx, raw, func() error { var err error; conn, err = c.protocol.DialEarlyXUDPPacketConn(raw, dst); return err })
	return conn, err
}
