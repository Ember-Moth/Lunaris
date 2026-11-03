// SPDX-License-Identifier: GPL-3.0-only
package outbound

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/route"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/protocol/socks/socks5"
)

type socksFactory struct{ kind string }

func (f socksFactory) name() string {
	if f.kind == "" {
		return "socks5"
	}
	return f.kind
}

func (f socksFactory) Capabilities() Capabilities {
	return Capabilities{Protocol: f.name(), TCP: true, UDP: f.name() == "socks5"}
}
func (f socksFactory) Normalize(s model.OutboundSpec, secret []byte) (json.RawMessage, error) {
	if f.name() != "socks5" {
		var options authOptions
		if err := decodeOptions(s.Options, &options); err != nil {
			return nil, err
		}
		if s.CredentialRef != "" || len(options.Username) > 255 || strings.ContainsAny(options.Username, "\x00\r\n") {
			return nil, errors.New("SOCKS4/4a accepts a user id but no password credential")
		}
		return json.Marshal(options)
	}
	return normalizeAuth(s, secret, true)
}
func (f socksFactory) Build(_ context.Context, s model.OutboundSpec, secret []byte, d N.Dialer, _ model.Limits) (ProtocolClient, error) {
	var options authOptions
	_ = json.Unmarshal(s.Options, &options)
	return &socksClient{kind: f.name(), dialer: d, server: M.ParseSocksaddrHostPort(s.Address, s.Port), username: options.Username, password: string(secret)}, nil
}

type socksClient struct {
	dialer             N.Dialer
	server             M.Socksaddr
	username, password string
	kind               string
}

func (*socksClient) Close() error { return nil }
func (c *socksClient) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	if network != "tcp" {
		return nil, ErrUnsupportedNetwork
	}
	if c.kind == "socks4" && dst.IsFqdn() {
		addresses, ok := route.ResolvedAddressesFromContext(ctx, dst.Fqdn)
		if !ok {
			var err error
			if resolver := route.NameResolverFromContext(ctx); resolver != nil {
				addresses, err = resolver.LookupIP(ctx, dst.Fqdn)
			} else {
				addresses, err = net.DefaultResolver.LookupNetIP(ctx, "ip4", dst.Fqdn)
			}
			if err != nil {
				return nil, err
			}
		}
		found := false
		for _, ip := range addresses {
			if ip.Unmap().Is4() {
				dst = M.Socksaddr{Addr: ip.Unmap(), Port: dst.Port}
				found = true
				break
			}
		}
		if !found {
			return nil, errors.New("SOCKS4 destination has no IPv4 address")
		}
	}
	if c.kind != "socks5" && !dst.IsFqdn() && !dst.Addr.Unmap().Is4() {
		return nil, errors.New("SOCKS4/4a cannot encode IPv6 destinations")
	}
	conn, err := c.dialer.DialContext(ctx, "tcp", c.server)
	if err != nil {
		return nil, err
	}
	err = handshake(ctx, conn, func() error {
		if c.kind != "socks5" {
			_, err := socks.ClientHandshake4(conn, 1, dst, c.username)
			return err
		}
		_, err := socks.ClientHandshake5(conn, socks5.CommandConnect, dst, c.username, c.password)
		return err
	})
	if err != nil {
		return nil, err
	}
	return conn, nil
}
func (c *socksClient) ListenPacket(ctx context.Context, dst M.Socksaddr) (net.PacketConn, error) {
	if c.kind != "socks5" {
		return nil, ErrUnsupportedNetwork
	}
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
