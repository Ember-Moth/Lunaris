// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

// Package native implements the Mieru server wire protocol without embedding
// the upstream Mieru application runtime.
package native

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

var (
	ErrInvalidOptions   = errors.New("sing-mieru: invalid server options")
	ErrInvalidTransport = errors.New("sing-mieru: invalid transport")
)

type Transport uint8

const (
	TransportTCP Transport = iota + 1
	TransportUDP
)

type User struct {
	Name     string
	Password string
}

type PreparedUsers struct{ snapshot *userSnapshot }

type StreamListenerFactory interface {
	Listen(ctx context.Context, network, address string) (net.Listener, error)
}

type PacketListenerFactory interface {
	ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error)
}

type ServerOptions struct {
	MaxPending          int
	OnAuthenticated     func(context.Context)
	MaxSessions         int
	QueueSize           int
	HandshakeTimeout    time.Duration
	IdleTimeout         time.Duration
	WriteTimeout        time.Duration
	Context             context.Context
	ListenAddress       string
	Transport           Transport
	MTU                 int
	Users               []User
	PreparedUsers       *PreparedUsers
	TrafficPattern      string
	UserHintIsMandatory bool
	TCPHandler          N.TCPConnectionHandlerEx
	UDPHandler          N.UDPConnectionHandlerEx
	StreamFactory       StreamListenerFactory
	PacketFactory       PacketListenerFactory
	Logger              logger.ContextLogger
	OnError             func(context.Context, error)
}
