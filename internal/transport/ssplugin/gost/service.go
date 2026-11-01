// SPDX-License-Identifier: GPL-3.0-or-later
// Adapted from Polaris; see THIRD_PARTY_NOTICES.md.
package gost

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/smux"

	carrier "github.com/Ember-Moth/Lunaris/internal/transport/ssplugin/websocket"
)

// Config is the validated gost-plugin configuration: its WebSocket carrier and
// smux limits.
type Config struct {
	WebSocket        carrier.Config
	Mux              bool
	MaxStreams       int
	MaxActiveStreams int
	HandshakeTimeout time.Duration
}

const (
	defaultMaxStreams       = 64
	defaultMaxActiveStreams = 4096
	defaultHandshakeTimeout = 10 * time.Second
	maximumMaxStreams       = 65535
	maximumActiveStreams    = 1 << 20
	maximumHandshakeTimeout = 5 * time.Minute
)

// ConnectionService receives the streams the plugin unwraps.
type ConnectionService interface {
	NewConnection(context.Context, net.Conn, M.Metadata) error
}

// ErrorHandler reports stream failures that do not belong to one connection.
type ErrorHandler func(context.Context, error)

// Service unwraps gost-plugin carriers, demultiplexing smux sessions when
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
	if config.MaxStreams <= 0 {
		config.MaxStreams = defaultMaxStreams
	} else {
		config.MaxStreams = min(config.MaxStreams, maximumMaxStreams)
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
func (service *Service) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) (result error) {
	if !service.config.Mux {
		return service.downstream.NewConnection(ctx, conn, metadata)
	}
	// The listener deadline protects the physical Shadowsocks handshake. In
	// mux mode that handshake runs on each virtual stream, so the deadline must
	// not remain attached to the shared carrier.
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	config := smux.DefaultConfig()
	config.KeepAliveDisabled = true
	config.MaxFrameSize = 16 * 1024

	session, err := smux.Server(conn, config)
	if err != nil {
		return err
	}
	var wait sync.WaitGroup
	streamSlots := make(chan struct{}, service.config.MaxStreams)
	done := make(chan struct{})
	defer func() {
		close(done)
		result = errors.Join(result, session.Close())
		wait.Wait()
	}()
	go func() {
		select {
		case <-ctx.Done():
			_ = session.Close()
		case <-done:
		}
	}()
	for {
		stream, acceptErr := session.AcceptStream()
		if acceptErr != nil {
			if ctx.Err() != nil || errors.Is(acceptErr, net.ErrClosed) || errors.Is(acceptErr, io.EOF) ||
				errors.Is(acceptErr, io.ErrClosedPipe) {
				return nil
			}
			return acceptErr
		}
		select {
		case streamSlots <- struct{}{}:
		default:
			_ = stream.Close()
			continue
		}
		if !service.acquireStream() {
			<-streamSlots
			_ = stream.Close()
			continue
		}
		if deadlineErr := stream.SetReadDeadline(time.Now().Add(service.config.HandshakeTimeout)); deadlineErr != nil {
			service.releaseStream()
			<-streamSlots
			_ = stream.Close()
			service.report(ctx, deadlineErr)
			continue
		}
		wait.Go(func() {
			defer service.releaseStream()
			defer func() { <-streamSlots }()
			defer func() { _ = stream.Close() }()
			if streamErr := service.downstream.NewConnection(ctx, stream, metadata); streamErr != nil {
				service.report(ctx, streamErr)
			}
		})
	}
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

func (service *Service) report(ctx context.Context, err error) {
	if service.onError != nil {
		service.onError(ctx, err)
	}
}
