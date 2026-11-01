// SPDX-License-Identifier: GPL-3.0-only
package transport

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type ServeFunc func(context.Context, net.Conn, M.Socksaddr, N.CloseHandlerFunc) error

// socketServer owns the listening socket and every carrier, including hijacked HTTP
// connections and multiplexed streams. Protocol handlers own no listener.
type socketServer struct {
	Spec            ResolvedSpec
	Limits          model.Limits
	TLS             *tls.Config
	prepare         func(context.Context) error
	cleanup         func()
	handshake       func(context.Context, net.Conn) (net.Conn, error)
	upgrade         func(*socketServer, http.ResponseWriter, *http.Request)
	packet          *PacketHandler
	udp             net.PacketConn
	closeErr        error
	Serve           ServeFunc
	OnStart         func() error
	OnClose         func() error
	mu              sync.Mutex
	ctx             context.Context
	cancel          context.CancelFunc
	listener        net.Listener
	http            *http.Server
	started, closed bool
	conns           map[*trackedConn]struct{}
	pending         chan struct{}
	wg              sync.WaitGroup
	once            sync.Once
	events          chan InstanceEvent
	done            chan struct{}
}

func newSocketServer(spec ResolvedSpec, binding Binding, upgrade func(*socketServer, http.ResponseWriter, *http.Request)) (*socketServer, error) {
	if err := model.ValidateLimits(spec.Limits); err != nil {
		return nil, err
	}
	if len(spec.Network) == 0 {
		spec.Network = []string{"tcp"}
	}
	for _, network := range spec.Network {
		if network == "tcp" && (binding.Stream == nil || binding.Stream.Serve == nil) {
			return nil, errors.New("transport requires a stream protocol handler")
		}
		if network == "udp" && (binding.Packet == nil || binding.Packet.Serve == nil) {
			return nil, errors.New("transport requires a packet protocol handler")
		}
		if network != "tcp" && network != "udp" {
			return nil, errors.New("unknown socket network")
		}
	}
	var alpn []string
	if upgrade != nil {
		alpn = []string{"http/1.1"}
	}
	tlsConfig, err := serverTLSConfig(spec, alpn)
	if err != nil {
		return nil, err
	}
	s := &socketServer{Spec: spec, Limits: spec.Limits, TLS: tlsConfig, upgrade: upgrade, packet: binding.Packet, conns: make(map[*trackedConn]struct{}), pending: make(chan struct{}, spec.Limits.MaxPendingHandshakes), events: make(chan InstanceEvent, 4), done: make(chan struct{})}
	if binding.Stream != nil {
		s.Serve = binding.Stream.Serve
		s.OnStart = binding.Stream.Start
		s.OnClose = binding.Stream.Close
	}
	return s, nil
}

func (s *socketServer) Events() <-chan InstanceEvent { return s.events }
func (s *socketServer) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		if s.udp != nil {
			return s.udp.LocalAddr()
		}
		return nil
	}
	return s.listener.Addr()
}
func (s *socketServer) Start(parent context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started || s.closed {
		return errors.New("stream instance cannot be restarted")
	}
	if err := parent.Err(); err != nil {
		return err
	}
	s.started = true
	s.ctx, s.cancel = context.WithCancel(parent)
	if s.prepare != nil {
		if err := s.prepare(s.ctx); err != nil {
			return err
		}
	}
	if s.OnStart != nil {
		if err := s.OnStart(); err != nil {
			return err
		}
	}
	address := net.JoinHostPort(s.Spec.Address, strconv.Itoa(int(s.Spec.Port)))
	var err error
	if slices.Contains(s.Spec.Network, "tcp") {
		s.listener, err = (&net.ListenConfig{}).Listen(s.ctx, "tcp", address)
		if err != nil {
			return err
		}
		if s.Spec.Port == 0 {
			address = s.listener.Addr().String()
		}
	}
	if slices.Contains(s.Spec.Network, "udp") {
		s.udp, err = (&net.ListenConfig{}).ListenPacket(s.ctx, "udp", address)
		if err != nil {
			if s.listener != nil {
				s.listener.Close()
			}
			return err
		}
	}
	context.AfterFunc(s.ctx, s.close)
	if s.listener != nil {
		s.wg.Add(1)
		if s.upgrade != nil {
			s.http = &http.Server{Handler: http.HandlerFunc(s.serveHTTP), ReadHeaderTimeout: s.Limits.HandshakeTimeout, MaxHeaderBytes: 8192, ConnContext: func(ctx context.Context, c net.Conn) context.Context {
				return context.WithValue(s.ctx, carrierKey{}, c.(*trackedConn))
			}}
			s.http.SetKeepAlivesEnabled(false)
			go func() { defer s.wg.Done(); s.failed(s.http.Serve(&streamListener{Listener: s.listener, server: s})) }()
		} else {
			go s.accept()
		}
	}
	if s.udp != nil {
		s.wg.Add(1)
		go func() { defer s.wg.Done(); s.failed(s.packet.Serve(s.ctx, s.udp)) }()
	}
	s.events <- InstanceEvent{State: "running"}
	return nil
}
func (s *socketServer) failed(err error) {
	s.mu.Lock()
	closed := s.closed || s.ctx.Err() != nil
	s.mu.Unlock()
	if !closed {
		select {
		case s.events <- InstanceEvent{State: "failed", Err: errors.New("transport listener failed")}:
		default:
		}
		s.close()
	}
}
func (s *socketServer) accept() {
	defer s.wg.Done()
	l := &streamListener{Listener: s.listener, server: s}
	for {
		c, err := l.Accept()
		if err != nil {
			s.failed(err)
			return
		}
		s.wg.Add(1)
		go func() { defer s.wg.Done(); s.serve(context.WithValue(s.ctx, carrierKey{}, c.(*trackedConn)), c) }()
	}
}
func (s *socketServer) serve(ctx context.Context, c net.Conn) {
	carrier := ctx.Value(carrierKey{}).(*trackedConn)
	// net/http clears deadlines during Hijack. Restore the original admission
	// deadline so an upgraded client cannot hold a handshake slot forever.
	_ = carrier.SetDeadline(carrier.deadline)
	defer func() { carrier.Close(); c.Close() }()
	if s.handshake != nil {
		wrapped, err := s.handshake(ctx, c)
		if err != nil {
			return
		}
		c = wrapped
	}
	err := s.Serve(ctx, c, M.SocksaddrFromNet(carrier.RemoteAddr()).Unwrap(), func(error) { carrier.Close() })
	if err == nil {
		select {
		case <-carrier.done:
		case <-s.ctx.Done():
		}
	}
}
func (s *socketServer) serveHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.wg.Add(1)
	s.mu.Unlock()
	defer s.wg.Done()
	if r.Method != "GET" || r.URL.EscapedPath() != s.Spec.Transport.Path || (s.Spec.Transport.Host != "" && !strings.EqualFold(r.Host, s.Spec.Transport.Host)) || r.ContentLength > 0 || len(r.TransferEncoding) > 0 {
		w.Header().Set("Connection", "close")
		http.NotFound(w, r)
		return
	}
	s.upgrade(s, w, r)
}

func headerToken(v, want string) bool {
	for _, v := range strings.Split(v, ",") {
		if strings.EqualFold(strings.TrimSpace(v), want) {
			return true
		}
	}
	return false
}
func (s *socketServer) close() {
	s.once.Do(func() {
		s.mu.Lock()
		s.closed = true
		if s.cancel != nil {
			s.cancel()
		}
		l, h, udp := s.listener, s.http, s.udp
		cs := make([]*trackedConn, 0, len(s.conns))
		for c := range s.conns {
			cs = append(cs, c)
		}
		s.mu.Unlock()
		go func() {
			if l != nil {
				l.Close()
			}
			if h != nil {
				h.Close()
			}
			for _, c := range cs {
				c.Close()
			}
			if udp != nil {
				udp.Close()
			}
			if s.packet != nil && s.packet.Close != nil {
				// Stop's caller bounds its wait, while cleanup keeps ownership
				// until completion so a later Stop can confirm resource release.
				s.closeErr = errors.Join(s.closeErr, s.packet.Close(context.Background()))
			}
			s.wg.Wait()
			if s.OnClose != nil {
				s.closeErr = errors.Join(s.closeErr, s.OnClose())
			}
			if s.cleanup != nil {
				s.cleanup()
			}
			s.events <- InstanceEvent{State: "stopped"}
			close(s.done)
		}()
	})
}
func (s *socketServer) Stop(ctx context.Context) error {
	s.close()
	select {
	case <-s.done:
		return s.closeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

type carrierKey struct{}
type trackedConn struct {
	net.Conn
	raw      net.Conn
	server   *socketServer
	once     sync.Once
	ready    sync.Once
	done     chan struct{}
	deadline time.Time
}

func (c *trackedConn) authenticated() {
	c.ready.Do(func() { _ = c.Conn.SetDeadline(time.Time{}); <-c.server.pending })
}
func (c *trackedConn) Close() error {
	var err error
	c.once.Do(func() {
		// Revoke the socket first; TLS/WebSocket close notifications must not
		// hold the listener's shutdown or admission budget waiting for a peer.
		err = c.raw.Close()
		_ = c.Conn.Close()
		c.authenticated()
		c.server.mu.Lock()
		delete(c.server.conns, c)
		c.server.mu.Unlock()
		close(c.done)
	})
	return err
}
func (c *trackedConn) CloseRead() error  { return N.CloseRead(c.Conn) }
func (c *trackedConn) CloseWrite() error { return N.CloseWrite(c.Conn) }

type streamListener struct {
	net.Listener
	server *socketServer
}

func (l *streamListener) Accept() (net.Conn, error) {
	for {
		raw, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		s := l.server
		s.mu.Lock()
		if s.closed || len(s.conns) >= s.Limits.MaxConnections {
			s.mu.Unlock()
			raw.Close()
			continue
		}
		select {
		case s.pending <- struct{}{}:
		default:
			s.mu.Unlock()
			raw.Close()
			continue
		}
		var conn net.Conn = raw
		if s.TLS != nil {
			conn = tls.Server(raw, s.TLS)
		}
		c := &trackedConn{Conn: conn, raw: raw, server: s, done: make(chan struct{}), deadline: time.Now().Add(s.Limits.HandshakeTimeout)}
		s.conns[c] = struct{}{}
		s.mu.Unlock()
		_ = c.SetDeadline(c.deadline)
		return c, nil
	}
}

// Bridge releases the carrier handshake budget only after protocol authentication.
type Bridge struct{ Handler RelayHandler }

type protocolReadyKey struct{}

// ReleaseHandshake releases carrier admission after the protocol authenticates it.
func ReleaseHandshake(ctx context.Context) { authenticated(ctx) }

func authenticated(ctx context.Context) {
	if ready, ok := ctx.Value(protocolReadyKey{}).(func()); ok {
		ready()
	}
	if c, ok := ctx.Value(carrierKey{}).(*trackedConn); ok {
		c.authenticated()
	}
}
func (b Bridge) NewConnectionEx(ctx context.Context, c net.Conn, src, dst M.Socksaddr, close N.CloseHandlerFunc) {
	authenticated(ctx)
	b.Handler.NewConnectionEx(ctx, c, src, dst, close)
}
func (b Bridge) NewPacketConnectionEx(ctx context.Context, c N.PacketConn, src, dst M.Socksaddr, close N.CloseHandlerFunc) {
	authenticated(ctx)
	b.Handler.NewPacketConnectionEx(ctx, c, src, dst, close)
}

type readerConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *readerConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (c *readerConn) CloseRead() error           { return N.CloseRead(c.Conn) }
func (c *readerConn) CloseWrite() error          { return N.CloseWrite(c.Conn) }

// FirstRead makes the upstream single-read auth parser tolerate TCP fragmentation.
type FirstRead struct {
	net.Conn
	Minimum int
	read    bool
}

func (c *FirstRead) Read(p []byte) (int, error) {
	if !c.read {
		c.read = true
		return io.ReadAtLeast(c.Conn, p, c.Minimum)
	}
	return c.Conn.Read(p)
}
