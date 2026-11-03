// SPDX-License-Identifier: GPL-3.0-only
package outbound

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"slices"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/gofrs/uuid/v5"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing-quic/tuic"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type hysteriaOptions struct {
	TLS          *TLSOptions `json:"tls,omitempty"`
	UploadMbps   uint32      `json:"upload_mbps,omitempty"`
	DownloadMbps uint32      `json:"download_mbps,omitempty"`
}
type hysteriaFactory struct{}

func (hysteriaFactory) Capabilities() Capabilities {
	return Capabilities{Protocol: "hysteria2", TCP: true, UDP: true}
}
func (hysteriaFactory) Normalize(s model.OutboundSpec, secret []byte) (json.RawMessage, error) {
	var o hysteriaOptions
	if err := decodeOptions(s.Options, &o); err != nil {
		return nil, err
	}
	if len(secret) == 0 {
		return nil, errors.New("Hysteria2 requires a password credential")
	}
	if (o.UploadMbps == 0) != (o.DownloadMbps == 0) || o.UploadMbps > 100000 || o.DownloadMbps > 100000 {
		return nil, errors.New("Hysteria2 bandwidth must be both zero (automatic) or 1-100000 Mbps")
	}
	var err error
	o.TLS, err = normalizeTLS(o.TLS, s.Address, true, true)
	if err != nil {
		return nil, err
	}
	return json.Marshal(o)
}
func (hysteriaFactory) Build(ctx context.Context, s model.OutboundSpec, secret []byte, d N.Dialer, limits model.Limits) (ProtocolClient, error) {
	var o hysteriaOptions
	_ = json.Unmarshal(s.Options, &o)
	cfg, err := o.TLS.config(true)
	if err != nil {
		return nil, err
	}
	return newSourcePool(ctx, d, limits.DialTimeout, func(root context.Context, dialer N.Dialer) (ProtocolClient, error) {
		client, err := hysteria2.NewClient(hysteria2.ClientOptions{Context: root, Dialer: dialer, Logger: logger.NOP(), ServerAddress: M.ParseSocksaddrHostPort(s.Address, s.Port), Password: string(secret), TLSConfig: &clientTLSConfig{config: cfg.Clone(), timeout: limits.HandshakeTimeout}, QUICOptions: qtls.QUICOptions{IdleTimeout: limits.UDPIdleTimeout}, SendBPS: uint64(o.UploadMbps) * 125000, ReceiveBPS: uint64(o.DownloadMbps) * 125000})
		if err != nil {
			return nil, err
		}
		return &quicClient{client: client, physical: dialer.(*ownedDialer)}, nil
	}), nil
}

type tuicOptions struct {
	UUID              string        `json:"uuid"`
	TLS               *TLSOptions   `json:"tls,omitempty"`
	CongestionControl string        `json:"congestion_control,omitempty"`
	UDPStream         bool          `json:"udp_stream,omitempty"`
	ZeroRTT           bool          `json:"zero_rtt,omitempty"`
	Heartbeat         time.Duration `json:"heartbeat,omitempty"`
}
type tuicFactory struct{}

func (tuicFactory) Capabilities() Capabilities {
	return Capabilities{Protocol: "tuic", TCP: true, UDP: true}
}
func (tuicFactory) Normalize(s model.OutboundSpec, secret []byte) (json.RawMessage, error) {
	var o tuicOptions
	if err := decodeOptions(s.Options, &o); err != nil {
		return nil, err
	}
	if len(secret) == 0 || !validUUID([]byte(o.UUID)) {
		return nil, errors.New("TUIC requires UUID and password credential")
	}
	if o.CongestionControl == "" {
		o.CongestionControl = "cubic"
	}
	if !slices.Contains([]string{"cubic", "new_reno", "bbr"}, o.CongestionControl) {
		return nil, errors.New("invalid TUIC congestion control")
	}
	if o.Heartbeat == 0 {
		o.Heartbeat = 10 * time.Second
	}
	if o.Heartbeat < time.Second || o.Heartbeat > time.Minute {
		return nil, errors.New("TUIC heartbeat must be between 1s and 1m")
	}
	var err error
	o.TLS, err = normalizeTLS(o.TLS, s.Address, true, true)
	if err != nil {
		return nil, err
	}
	return json.Marshal(o)
}
func (tuicFactory) Build(ctx context.Context, s model.OutboundSpec, secret []byte, d N.Dialer, limits model.Limits) (ProtocolClient, error) {
	var o tuicOptions
	_ = json.Unmarshal(s.Options, &o)
	cfg, err := o.TLS.config(true)
	if err != nil {
		return nil, err
	}
	id, _ := uuid.FromString(o.UUID)
	return newSourcePool(ctx, d, limits.DialTimeout, func(root context.Context, dialer N.Dialer) (ProtocolClient, error) {
		client, err := tuic.NewClient(tuic.ClientOptions{Context: root, Dialer: dialer, ServerAddress: M.ParseSocksaddrHostPort(s.Address, s.Port), UUID: [16]byte(id), Password: string(secret), TLSConfig: &clientTLSConfig{config: cfg.Clone(), timeout: limits.HandshakeTimeout}, QUICOptions: qtls.QUICOptions{IdleTimeout: limits.UDPIdleTimeout}, CongestionControl: o.CongestionControl, UDPStream: o.UDPStream, ZeroRTTHandshake: o.ZeroRTT, Heartbeat: o.Heartbeat})
		if err != nil {
			return nil, err
		}
		return &quicClient{client: client, physical: dialer.(*ownedDialer)}, nil
	}), nil
}

type quicProtocol interface {
	DialConn(context.Context, M.Socksaddr) (net.Conn, error)
	ListenPacket(context.Context) (net.PacketConn, error)
	CloseWithError(error) error
}
type quicClient struct {
	client   quicProtocol
	physical *ownedDialer
}

func (c *quicClient) Close() error { return c.client.CloseWithError(net.ErrClosed) }
func (c *quicClient) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	if network != "tcp" {
		return nil, ErrUnsupportedNetwork
	}
	conn, err := c.client.DialConn(ctx, dst)
	if err == nil {
		c.physical.ready()
	}
	return conn, err
}
func (c *quicClient) ListenPacket(ctx context.Context, _ M.Socksaddr) (net.PacketConn, error) {
	conn, err := c.client.ListenPacket(ctx)
	if err == nil {
		c.physical.ready()
		conn = &packetDeadline{NetPacketConn: bufio.NewPacketConn(conn)}
	}
	return conn, err
}
