// SPDX-License-Identifier: GPL-3.0-or-later
// Adapted from Polaris; see THIRD_PARTY_NOTICES.md.
package v2ray

import (
	"context"
	"net"
	"time"

	M "github.com/sagernet/sing/common/metadata"

	carrier "github.com/Ember-Moth/Lunaris/internal/transport/ssplugin/websocket"
)

// Config is the validated v2ray-plugin configuration: its WebSocket carrier and
// mux limits.
type Config struct {
	WebSocket             carrier.Config
	Mux                   bool
	MaxSessions           int
	MaxSessionQueuedBytes int
	MaxQueuedBytes        int
	MaxActiveStreams      int
	HandshakeTimeout      time.Duration
}

const (
	defaultMaxSessions           = 64
	defaultMaxSessionQueuedBytes = 256 * 1024
	defaultMaxQueuedBytes        = 1024 * 1024
	defaultMaxActiveStreams      = 4096
	defaultHandshakeTimeout      = 10 * time.Second
	maximumMaxSessions           = 65535
	maximumSessionQueuedBytes    = 64 * 1024 * 1024
	maximumQueuedBytes           = 256 * 1024 * 1024
	maximumActiveStreams         = 1 << 20
	maximumHandshakeTimeout      = 5 * time.Minute
)

// ConnectionService receives the streams the plugin unwraps.
type ConnectionService interface {
	NewConnection(context.Context, net.Conn, M.Metadata) error
}

// ErrorHandler reports stream failures that do not belong to one connection.
type ErrorHandler func(context.Context, error)

// Service unwraps v2ray-plugin carriers, demultiplexing its mux sessions when
// enabled.
type Service struct {
	config     Config
	downstream ConnectionService
	onError    ErrorHandler
	streams    chan struct{}
}

// NewService applies the limit defaults and caps and wraps the downstream
// service.
func NewService(config Config, downstream ConnectionService, onError ErrorHandler) *Service {
	if config.MaxSessions <= 0 {
		config.MaxSessions = defaultMaxSessions
	} else {
		config.MaxSessions = min(config.MaxSessions, maximumMaxSessions)
	}
	if config.MaxSessionQueuedBytes <= 0 {
		config.MaxSessionQueuedBytes = defaultMaxSessionQueuedBytes
	} else {
		config.MaxSessionQueuedBytes = min(config.MaxSessionQueuedBytes, maximumSessionQueuedBytes)
	}
	if config.MaxQueuedBytes <= 0 {
		config.MaxQueuedBytes = defaultMaxQueuedBytes
	} else {
		config.MaxQueuedBytes = min(config.MaxQueuedBytes, maximumQueuedBytes)
	}
	if config.MaxSessionQueuedBytes > config.MaxQueuedBytes {
		config.MaxSessionQueuedBytes = config.MaxQueuedBytes
	}
	if config.MaxActiveStreams <= 0 {
		config.MaxActiveStreams = defaultMaxActiveStreams
	} else {
		config.MaxActiveStreams = min(config.MaxActiveStreams, maximumActiveStreams)
	}
	if config.HandshakeTimeout <= 0 {
		config.HandshakeTimeout = defaultHandshakeTimeout
	} else {
		config.HandshakeTimeout = min(config.HandshakeTimeout, maximumHandshakeTimeout)
	}
	return &Service{
		config: config, downstream: downstream, onError: onError,
		streams: make(chan struct{}, config.MaxActiveStreams),
	}
}

// NewConnection passes a plain carrier through, or serves every stream of a
// multiplexed one.
func (service *Service) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	if !service.config.Mux {
		return service.downstream.NewConnection(ctx, conn, metadata)
	}
	// The outer Shadowsocks listener arms a handshake deadline before the
	// WebSocket upgrade. Authentication moves to the virtual mux streams, so
	// leaving that deadline on the carrier tears down every session after the
	// listener timeout even while streams are active.
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	server := newMuxServer(conn, service)
	return server.serve(ctx, metadata)
}

func (service *Service) acquireStream() bool {
	select {
	case service.streams <- struct{}{}:
		return true
	default:
		return false
	}
}

func (service *Service) releaseStream() { <-service.streams }
