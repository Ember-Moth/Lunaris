// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Polaris contributors
package restls

import (
	"context"
	"errors"
	"net"

	engine "github.com/metacubex/restls-client-go"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var ErrInvalidConfig = errors.New("sing-restls: invalid server config")

type ServerConfig struct {
	Handshake    M.Socksaddr
	Password     string
	Script       string
	MinRecordLen int
	Dialer       N.Dialer
}

type Server struct {
	handshake    M.Socksaddr
	password     string
	script       string
	minRecordLen int
	dialer       N.Dialer
}

func NewServer(config ServerConfig) (*Server, error) {
	if !config.Handshake.IsValid() || config.Handshake.Port == 0 || config.Password == "" || config.MinRecordLen < 0 {
		return nil, ErrInvalidConfig
	}
	if config.Dialer == nil {
		config.Dialer = N.SystemDialer
	}
	return &Server{
		handshake:    config.Handshake,
		password:     config.Password,
		script:       config.Script,
		minRecordLen: config.MinRecordLen,
		dialer:       config.Dialer,
	}, nil
}

func (server *Server) NewConnection(ctx context.Context, inbound net.Conn) (net.Conn, error) {
	if inbound == nil {
		return nil, ErrInvalidConfig
	}
	trackedInbound := newRecordTrackingConn(inbound)
	wrapped, err := engine.RestlsServer(ctx, trackedInbound, &engine.RestlsServerConfig{
		ServerHostname: server.handshake.String(),
		Password:       server.password,
		RestlsScript:   server.script,
		MinRecordLen:   server.minRecordLen,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return server.dialer.DialContext(ctx, network, server.handshake)
		},
	})
	if err != nil {
		return nil, err
	}
	return newConn(wrapped, trackedInbound), nil
}
