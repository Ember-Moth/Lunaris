// SPDX-License-Identifier: GPL-3.0-only
package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
	Q "github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	qtls "github.com/sagernet/sing-quic"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
	"golang.org/x/net/http2"
)

// HTTPFactory owns TLS and HTTP/1.1 or HTTP/2 connections. The protocol binding
// authenticates requests and owns only their CONNECT streams.
type HTTPFactory struct{}

func (HTTPFactory) Capabilities() Capabilities {
	return Capabilities{Type: "http", TCP: true, TLS: true}
}
func (HTTPFactory) Validate(s model.ListenerSpec) []model.FieldError {
	if s.CertificateRef == "" {
		return field("certificate_ref", "HTTP proxy transport requires TLS")
	}
	return validatePlain(s)
}
func (HTTPFactory) Build(r ResolvedSpec, b Binding) (Instance, error) {
	if b.HTTP == nil {
		return nil, errors.New("HTTP protocol handler required")
	}
	binding := Binding{Stream: &StreamHandler{Serve: func(ctx context.Context, c net.Conn, _ M.Socksaddr, _ N.CloseHandlerFunc) error {
		tracked := c.(*trackedConn)
		secure, ok := tracked.Conn.(*tls.Conn)
		if !ok {
			return errors.New("HTTP proxy transport requires TLS")
		}
		if err := secure.HandshakeContext(ctx); err != nil {
			return err
		}
		server := &http.Server{Handler: b.HTTP, ReadHeaderTimeout: r.Limits.HandshakeTimeout, IdleTimeout: r.Limits.UDPIdleTimeout, MaxHeaderBytes: 8192, BaseContext: func(net.Listener) context.Context { return ctx }}
		if secure.ConnectionState().NegotiatedProtocol == http2.NextProtoTLS {
			h2 := &http2.Server{MaxConcurrentStreams: uint32(r.Limits.MaxConnections + r.Limits.MaxUDPSessions), IdleTimeout: r.Limits.UDPIdleTimeout, MaxReadFrameSize: 1 << 20, MaxUploadBufferPerConnection: 4 << 20, MaxUploadBufferPerStream: 1 << 20}
			h2.ServeConn(&httpTLSConn{Conn: c, state: secure.ConnectionState()}, &http2.ServeConnOpts{Context: ctx, BaseConfig: server, Handler: b.HTTP})
			return nil
		}
		server.SetKeepAlivesEnabled(false)
		_ = server.Serve(&singleHTTPListener{Conn: c, done: tracked.done})
		return nil
	}}}
	s, err := newSocketServer(r, binding, nil)
	if err != nil {
		return nil, err
	}
	if s.TLS == nil {
		return nil, errors.New("HTTP proxy transport requires TLS")
	}
	s.TLS.NextProtos = []string{http2.NextProtoTLS, "http/1.1"}
	return s, nil
}

type httpTLSConn struct {
	net.Conn
	state tls.ConnectionState
}

func (c *httpTLSConn) ConnectionState() tls.ConnectionState { return c.state }

type singleHTTPListener struct {
	net.Conn
	used bool
	done <-chan struct{}
}

func (l *singleHTTPListener) Accept() (net.Conn, error) {
	if !l.used {
		l.used = true
		return l.Conn, nil
	}
	<-l.done
	return nil, net.ErrClosed
}
func (l *singleHTTPListener) Addr() net.Addr { return l.Conn.LocalAddr() }

// HTTP/3 uses the existing QUIC transport's socket ownership and connection
// limits. It shares the same protocol HTTP handler as HTTP/1.1 and HTTP/2.
func http3Binding(handler http.Handler, timeout time.Duration) *QUICHandler {
	return &QUICHandler{ALPN: []string{"h3"}, NewService: func(ctx context.Context, cfg aTLS.ServerConfig, options qtls.QUICOptions) (QUICService, error) {
		tlsConfig, ok := cfg.(qtls.ServerConfig)
		if !ok {
			return nil, errors.New("QUIC TLS adapter required")
		}
		return &http3Service{ctx: ctx, tls: tlsConfig, options: options, server: &http3.Server{Handler: handler, ConnContext: func(ctx context.Context, c *Q.Conn) context.Context {
			timer := time.AfterFunc(timeout, func() { _ = c.CloseWithError(0, "authentication timeout") })
			context.AfterFunc(c.Context(), func() { timer.Stop() })
			return context.WithValue(ctx, protocolReadyKey{}, func() { timer.Stop() })
		}, MaxHeaderBytes: 8192, IdleTimeout: options.IdleTimeout}, done: make(chan struct{})}, nil
	}}
}

type http3Service struct {
	ctx      context.Context
	tls      qtls.ServerConfig
	options  qtls.QUICOptions
	server   *http3.Server
	listener qtls.Listener
	done     chan struct{}
	once     sync.Once
}

func (s *http3Service) Start(c net.PacketConn) error {
	cfg := &Q.Config{Allow0RTT: false}
	qtls.ApplyQUICOptions(cfg, s.options)
	var err error
	s.listener, err = s.tls.Listen(c, cfg)
	if err != nil {
		return err
	}
	go func() { defer close(s.done); _ = s.server.ServeListener(s.listener) }()
	return nil
}
func (s *http3Service) Close() error {
	var err error
	s.once.Do(func() {
		err = s.server.Close()
		if s.listener != nil {
			s.listener.Close()
			<-s.done
		}
	})
	return err
}
