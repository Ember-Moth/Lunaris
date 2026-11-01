// SPDX-License-Identifier: GPL-3.0-or-later
// Adapted from Polaris; see THIRD_PARTY_NOTICES.md.
package shadowtls

import (
	"context"
	"io"
	"net"
	"sync"

	protocol "github.com/sagernet/sing-shadowtls"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Config is the validated ShadowTLS configuration.
type Config struct {
	Dialer           N.Dialer
	Version          int
	Password         string
	HandshakeAddress string
	StrictMode       bool
}

// ConnectionService receives the streams the plugin unwraps.
type ConnectionService interface {
	NewConnection(context.Context, net.Conn, M.Metadata) error
}

// Service terminates ShadowTLS handshakes in front of the Shadowsocks service.
type Service struct {
	service *protocol.Service
}

// NewService builds the ShadowTLS service with a single password shared by every
// user.
func NewService(config Config, downstream ConnectionService) (*Service, error) {
	if config.Dialer == nil {
		config.Dialer = N.SystemDialer
	}
	adapter := &downstreamAdapter{service: downstream}
	service, err := protocol.NewService(protocol.ServiceConfig{
		Version:  config.Version,
		Password: config.Password,
		Users: []protocol.User{{
			Name: "shadowsocks", Password: config.Password,
		}},
		Handshake: protocol.HandshakeConfig{
			Server: M.ParseSocksaddr(config.HandshakeAddress), Dialer: config.Dialer,
		},
		StrictMode: config.StrictMode,
		Handler:    adapter,
		Logger:     logger.NOP(),
	})
	if err != nil {
		return nil, err
	}
	return &Service{service: service}, nil
}

// NewConnection completes the ShadowTLS handshake and passes the inner stream
// downstream.
func (service *Service) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	result := &connectionResult{}
	ctx = context.WithValue(ctx, resultKey{}, result)
	err := service.service.NewConnection(ctx, conn, metadata.Source, metadata.Destination, nil)
	if err != nil {
		return err
	}
	return result.err
}

type (
	resultKey        struct{}
	connectionResult struct{ err error }
)

type downstreamAdapter struct{ service ConnectionService }

func (adapter *downstreamAdapter) NewConnectionEx(
	ctx context.Context,
	conn net.Conn,
	source, destination M.Socksaddr,
	_ N.CloseHandlerFunc,
) {
	err := adapter.service.NewConnection(ctx, &serializedConn{Conn: conn}, M.Metadata{Source: source, Destination: destination})
	if result, ok := ctx.Value(resultKey{}).(*connectionResult); ok {
		result.err = err
	}
}

var _ N.TCPConnectionHandlerEx = (*downstreamAdapter)(nil)

// Hide upstream vector/buffer fast paths: v0.2.1 computes an invalid v3 HMAC
// on vector writes and does not split WriteBuffer at the TLS record limit.
// Serialize record-sized calls and stop at the first failed write.
type serializedConn struct {
	net.Conn
	writeMu sync.Mutex
}

func (c *serializedConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	n := 0
	for len(p) > 0 {
		chunk := p[:min(16384, len(p))]
		m, err := c.Conn.Write(chunk)
		n += m
		if err != nil {
			return n, err
		}
		if m != len(chunk) {
			return n, io.ErrShortWrite
		}
		p = p[m:]
	}
	return n, nil
}
func (c *serializedConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return c.Conn.Read(p)
}
