// SPDX-License-Identifier: GPL-3.0-only
package outbound

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"slices"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
	ss "github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type ssOptions struct {
	Method string `json:"method"`
}
type shadowsocksFactory struct{}

func (shadowsocksFactory) Capabilities() Capabilities {
	return Capabilities{Protocol: "shadowsocks", TCP: true, UDP: true, Methods: append([]string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"}, shadowaead_2022.List...)}
}
func (f shadowsocksFactory) Normalize(s model.OutboundSpec, secret []byte) (json.RawMessage, error) {
	var options ssOptions
	if err := decodeOptions(s.Options, &options); err != nil {
		return nil, err
	}
	if !slices.Contains(f.Capabilities().Methods, options.Method) || len(secret) == 0 {
		return nil, errors.New("invalid Shadowsocks method or credential")
	}
	if slices.Contains(shadowaead_2022.List, options.Method) {
		size := 32
		if options.Method == "2022-blake3-aes-128-gcm" {
			size = 16
		}
		key, err := base64.StdEncoding.Strict().DecodeString(string(secret))
		if err != nil || len(key) != size || base64.StdEncoding.EncodeToString(key) != string(secret) {
			return nil, errors.New("Shadowsocks 2022 requires a canonical base64 key of the method's key size")
		}
	}
	return json.Marshal(options)
}
func (shadowsocksFactory) Build(s model.OutboundSpec, secret []byte, d N.Dialer) (ProtocolClient, error) {
	var options ssOptions
	_ = json.Unmarshal(s.Options, &options)
	var method ss.Method
	var err error
	if slices.Contains(shadowaead_2022.List, options.Method) {
		method, err = shadowaead_2022.NewWithPassword(options.Method, string(secret), time.Now)
	} else {
		method, err = shadowaead.New(options.Method, nil, string(secret))
	}
	if err != nil {
		return nil, errors.New("cannot initialize Shadowsocks outbound cipher")
	}
	return &shadowsocksClient{dialer: d, server: M.ParseSocksaddrHostPort(s.Address, s.Port), method: method}, nil
}

type shadowsocksClient struct {
	dialer N.Dialer
	server M.Socksaddr
	method ss.Method
}

func (*shadowsocksClient) Close() error { return nil }
func (c *shadowsocksClient) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	if network != "tcp" {
		return nil, ErrUnsupportedNetwork
	}
	raw, err := c.dialer.DialContext(ctx, "tcp", c.server)
	if err != nil {
		return nil, err
	}
	var conn net.Conn
	err = handshake(ctx, raw, func() error { var err error; conn, err = c.method.DialConn(raw, dst); return err })
	if err != nil {
		return nil, err
	}
	return conn, nil
}
func (c *shadowsocksClient) ListenPacket(ctx context.Context, _ M.Socksaddr) (net.PacketConn, error) {
	raw, err := c.dialer.DialContext(ctx, "udp", c.server)
	if err != nil {
		return nil, err
	}
	return c.method.DialPacketConn(raw), nil
}
