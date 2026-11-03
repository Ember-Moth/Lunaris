// SPDX-License-Identifier: GPL-3.0-only
package outbound

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"sync"

	"github.com/Ember-Moth/Lunaris/internal/model"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/protocol/socks/socks5"
)

type socksFactory struct{}

func (socksFactory) Capabilities() Capabilities {
	return Capabilities{Protocol: "socks5", TCP: true, UDP: true}
}
func (socksFactory) Normalize(s model.OutboundSpec, secret []byte) (json.RawMessage, error) {
	return normalizeAuth(s, secret, true)
}
func (socksFactory) Build(s model.OutboundSpec, secret []byte, d N.Dialer) (ProtocolClient, error) {
	var options authOptions
	_ = json.Unmarshal(s.Options, &options)
	return &socksClient{dialer: d, server: M.ParseSocksaddrHostPort(s.Address, s.Port), username: options.Username, password: string(secret)}, nil
}

type socksClient struct {
	dialer             N.Dialer
	server             M.Socksaddr
	username, password string
}

func (*socksClient) Close() error { return nil }
func (c *socksClient) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	if network != "tcp" {
		return nil, ErrUnsupportedNetwork
	}
	conn, err := c.dialer.DialContext(ctx, "tcp", c.server)
	if err != nil {
		return nil, err
	}
	err = handshake(ctx, conn, func() error {
		_, err := socks.ClientHandshake5(conn, socks5.CommandConnect, dst, c.username, c.password)
		return err
	})
	if err != nil {
		return nil, err
	}
	return conn, nil
}
func (c *socksClient) ListenPacket(ctx context.Context, dst M.Socksaddr) (net.PacketConn, error) {
	control, err := c.dialer.DialContext(ctx, "tcp", c.server)
	if err != nil {
		return nil, err
	}
	var reply socks5.Response
	err = handshake(ctx, control, func() error {
		var err error
		reply, err = socks.ClientHandshake5(control, socks5.CommandUDPAssociate, M.Socksaddr{Addr: netip.IPv4Unspecified()}, c.username, c.password)
		return err
	})
	if err != nil {
		return nil, err
	}
	relay := reply.Bind.Unwrap()
	if relay.Addr.IsUnspecified() {
		relay.Addr = M.SocksaddrFromNet(control.RemoteAddr()).Addr
	}
	if !relay.IsValid() || relay.Port == 0 {
		control.Close()
		return nil, errors.New("SOCKS5 returned an invalid UDP relay")
	}
	udp, err := c.dialer.DialContext(ctx, "udp", relay)
	if err != nil {
		control.Close()
		return nil, err
	}
	connection := &socksPacket{NetPacketConn: socks.NewAssociatePacketConn(socksDatagram{udp}, dst, control), done: make(chan struct{})}
	go func() {
		defer close(connection.done)
		var b [1]byte
		_, _ = control.Read(b[:])
		connection.NetPacketConn.Close()
	}()
	return connection, nil
}

type socksDatagram struct{ net.Conn }

func (c socksDatagram) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err == nil && (n < 4 || p[0] != 0 || p[1] != 0 || p[2] != 0) {
		return 0, errors.New("invalid or fragmented SOCKS5 UDP response")
	}
	return n, err
}

type socksPacket struct {
	N.NetPacketConn
	done chan struct{}
	once sync.Once
	err  error
}

func (c *socksPacket) Close() error {
	c.once.Do(func() { c.err = c.NetPacketConn.Close(); <-c.done })
	return c.err
}
