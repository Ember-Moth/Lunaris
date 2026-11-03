// SPDX-License-Identifier: GPL-3.0-only
package outbound

import (
	"context"
	"encoding/json"
	"net"
	"sync"

	"github.com/Ember-Moth/Lunaris/internal/model"
	anytls "github.com/sagernet/sing-anytls"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

type anytlsFactory struct{}

func (anytlsFactory) Capabilities() Capabilities {
	return Capabilities{Protocol: "anytls", TCP: true, UDP: true}
}
func (anytlsFactory) Normalize(s model.OutboundSpec, secret []byte) (json.RawMessage, error) {
	return normalizeTLSOnly(s, secret)
}
func (anytlsFactory) Build(ctx context.Context, s model.OutboundSpec, secret []byte, d N.Dialer, limits model.Limits) (ProtocolClient, error) {
	var o tlsOnlyOptions
	_ = json.Unmarshal(s.Options, &o)
	return newSourcePool(ctx, d, limits.DialTimeout, func(_ context.Context, dialer N.Dialer) (ProtocolClient, error) {
		carrier, err := newCarrier(s, o.TLS, dialer, limits)
		if err != nil {
			return nil, err
		}
		client, err := anytls.NewClient(anytls.ClientOptions{Password: string(secret), DialOut: func(ctx context.Context) (net.Conn, error) {
			conn, err := carrier.open(ctx)
			if err != nil {
				return nil, err
			}
			if err = handshake(ctx, conn, func() error { return nil }); err != nil {
				return nil, err
			}
			if guard, ok := ctx.Value(anytlsGuardKey{}).(*anytlsGuard); ok {
				guard.attach(conn)
			}
			return conn, nil
		}})
		if err != nil {
			return nil, err
		}
		return &anytlsClient{client: client}, nil
	}), nil
}

type anytlsClient struct{ client *anytls.Client }

func (c *anytlsClient) Close() error { return c.client.Close() }
func (c *anytlsClient) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	if network != "tcp" {
		return nil, ErrUnsupportedNetwork
	}
	guard := &anytlsGuard{}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { guard.close(); close(done) })
	conn, err := c.client.DialContext(context.WithValue(ctx, anytlsGuardKey{}, guard), dst)
	if !stop() {
		<-done
		if conn != nil {
			conn.Close()
		}
		return nil, ctx.Err()
	}
	if err != nil {
		guard.close()
	}
	return conn, err
}
func (c *anytlsClient) ListenPacket(ctx context.Context, dst M.Socksaddr) (net.PacketConn, error) {
	return (&uot.Client{Dialer: c, Version: 2}).ListenPacket(ctx, dst)
}

type anytlsGuardKey struct{}
type anytlsGuard struct {
	mu     sync.Mutex
	closed bool
	conn   net.Conn
}

func (g *anytlsGuard) attach(c net.Conn) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		c.Close()
	} else {
		g.conn = c
	}
}
func (g *anytlsGuard) close() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closed = true
	if g.conn != nil {
		g.conn.Close()
	}
}
