// SPDX-License-Identifier: MIT
// Derived and modified from github.com/MetaCubeX/mihomo transport/kcptun.

package kcptun

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/kcp-go"
	"github.com/sagernet/smux"
)

// Server accepts KCP sessions over a UDP socket and serves their smux streams.
type Server struct {
	config   Config
	sessions chan struct{}
	pending  chan struct{}
	streams  chan struct{}
}

const (
	defaultMaxSessions      = 1024
	defaultMaxStreams       = 64
	defaultMaxActiveStreams = 4096
)

var (
	errEmptyKey      = errors.New("shadowsocks: kcptun key is required")
	errInsecureCrypt = errors.New("shadowsocks: insecure kcptun crypt requires allow-insecure")
	errInvalidLimit  = errors.New("shadowsocks: invalid kcptun resource limit")
)

// NewServer validates the key, cipher and limits and builds the block cipher.
func NewServer(config Config) (*Server, error) {
	if strings.TrimSpace(config.Key) == "" {
		return nil, errEmptyKey
	}
	if insecureCrypt(config.Crypt) && !config.AllowInsecure {
		return nil, errInsecureCrypt
	}
	if config.MaxSessions > 1<<20 || config.MaxStreams > 65535 || config.MaxActiveStreams > 1<<20 {
		return nil, errInvalidLimit
	}
	if config.MaxSessions <= 0 {
		config.MaxSessions = defaultMaxSessions
	}
	if config.MaxStreams <= 0 {
		config.MaxStreams = defaultMaxStreams
	}
	if config.MaxActiveStreams <= 0 {
		config.MaxActiveStreams = defaultMaxActiveStreams
	}
	if config.MaxPendingSessions <= 0 {
		config.MaxPendingSessions = min(config.MaxSessions, 128)
	}
	if config.HandshakeTimeout <= 0 {
		config.HandshakeTimeout = 10 * time.Second
	}
	_, err := newBlock(config)
	if err != nil {
		return nil, err
	}
	return &Server{
		config:   config,
		sessions: make(chan struct{}, config.MaxSessions),
		pending:  make(chan struct{}, config.MaxPendingSessions),
		streams:  make(chan struct{}, config.MaxActiveStreams),
	}, nil
}

// Serve accepts KCP sessions on the socket and hands each stream to the handler
// until the socket closes.
func (server *Server) Serve(ctx context.Context, packetConn net.PacketConn, handler func(net.Conn)) error {
	block, err := newBlock(server.config)
	if err != nil {
		return err
	}
	listener, err := kcp.ServeConn(block, server.config.DataShard, server.config.ParityShard, packetConn)
	if err != nil {
		return err
	}
	var sessions sync.Map
	var wait sync.WaitGroup
	done := make(chan struct{})
	defer func() {
		close(done)
		_ = listener.Close()
		sessions.Range(func(key, _ any) bool {
			_ = key.(net.Conn).Close()
			return true
		})
		wait.Wait()
	}()
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-done:
		}
	}()
	_ = listener.SetDSCP(server.config.DSCP)
	_ = listener.SetReadBuffer(server.config.SockBuf)
	_ = listener.SetWriteBuffer(server.config.SockBuf)
	for {
		conn, acceptErr := listener.AcceptKCP()
		if acceptErr != nil {
			return acceptErr
		}
		configureKCP(conn, server.config)
		select {
		case server.sessions <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		select {
		case server.pending <- struct{}{}:
		default:
			<-server.sessions
			_ = conn.Close()
			continue
		}
		sessions.Store(conn, struct{}{})
		wait.Go(func() {
			defer func() { <-server.sessions }()
			defer sessions.Delete(conn)
			defer func() { _ = conn.Close() }()
			server.serveSession(ctx, conn, handler)
		})
	}
}

func (server *Server) serveSession(ctx context.Context, raw net.Conn, handler func(net.Conn)) {
	var readyOnce sync.Once
	ready := func() { readyOnce.Do(func() { <-server.pending }) }
	defer ready()
	timer := time.AfterFunc(server.config.HandshakeTimeout, func() { raw.Close() })
	defer timer.Stop()
	authenticated := func() { timer.Stop(); ready() }
	conn := raw
	if !server.config.NoComp {
		conn = newCompConn(conn)
	}
	session, err := smux.Server(conn, smuxConfig(server.config))
	if err != nil {
		_ = conn.Close()
		return
	}
	var wait sync.WaitGroup
	streamSlots := make(chan struct{}, server.config.MaxStreams)
	defer func() {
		_ = session.Close()
		wait.Wait()
	}()
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			return
		}
		select {
		case <-ctx.Done():
			_ = stream.Close()
			return
		case streamSlots <- struct{}{}:
		default:
			_ = stream.Close()
			continue
		}
		select {
		case server.streams <- struct{}{}:
		default:
			<-streamSlots
			_ = stream.Close()
			continue
		}
		wait.Go(func() {
			defer func() { <-server.streams }()
			defer func() { <-streamSlots }()
			defer func() { _ = stream.Close() }()
			handler(&admittedStream{Conn: stream, ready: authenticated})
		})
	}
}

// ProtocolReady is called only when the inner Shadowsocks protocol authenticates.
type admittedStream struct {
	net.Conn
	ready func()
}

func (c *admittedStream) ProtocolReady() { c.ready() }
