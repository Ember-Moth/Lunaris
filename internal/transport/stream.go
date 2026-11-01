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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/coder/websocket"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type ServeFunc func(context.Context, net.Conn, M.Socksaddr, N.CloseHandlerFunc) error

// Stream owns the listening socket and every carrier, including hijacked HTTP
// connections and multiplexed streams. Protocol handlers own no listener.
type Stream struct {
	Spec            model.ListenerSpec
	Limits          model.Limits
	TLS             *tls.Config
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
	events          chan protocol.InstanceEvent
	done            chan struct{}
}

func NewStream(spec model.ListenerSpec, limits model.Limits) *Stream {
	return &Stream{Spec: spec, Limits: limits, conns: make(map[*trackedConn]struct{}), pending: make(chan struct{}, limits.MaxPendingHandshakes), events: make(chan protocol.InstanceEvent, 4), done: make(chan struct{})}
}
func (s *Stream) Events() <-chan protocol.InstanceEvent { return s.events }
func (s *Stream) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}
func (s *Stream) Start(parent context.Context) error {
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
	if s.OnStart != nil {
		if err := s.OnStart(); err != nil {
			return err
		}
	}
	l, err := (&net.ListenConfig{}).Listen(s.ctx, "tcp", net.JoinHostPort(s.Spec.Address, strconv.Itoa(int(s.Spec.Port))))
	if err != nil {
		return err
	}
	s.listener = l
	context.AfterFunc(s.ctx, s.close)
	s.wg.Add(1)
	if s.Spec.Transport.Type == "ws" || s.Spec.Transport.Type == "httpupgrade" {
		s.http = &http.Server{Handler: http.HandlerFunc(s.serveHTTP), ReadHeaderTimeout: s.Limits.HandshakeTimeout, MaxHeaderBytes: 8192, ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(s.ctx, carrierKey{}, c.(*trackedConn))
		}}
		s.http.SetKeepAlivesEnabled(false)
		go func() { defer s.wg.Done(); s.failed(s.http.Serve(&streamListener{Listener: l, server: s})) }()
	} else {
		go s.accept()
	}
	s.events <- protocol.InstanceEvent{State: "running"}
	return nil
}
func (s *Stream) failed(err error) {
	s.mu.Lock()
	closed := s.closed || s.ctx.Err() != nil
	s.mu.Unlock()
	if !closed {
		select {
		case s.events <- protocol.InstanceEvent{State: "failed", Err: errors.New("transport listener failed")}:
		default:
		}
		s.close()
	}
}
func (s *Stream) accept() {
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
func (s *Stream) serve(ctx context.Context, c net.Conn) {
	carrier := ctx.Value(carrierKey{}).(*trackedConn)
	// net/http clears deadlines during Hijack. Restore the original admission
	// deadline so an upgraded client cannot hold a handshake slot forever.
	_ = carrier.SetDeadline(carrier.deadline)
	defer func() { carrier.Close(); c.Close() }()
	err := s.Serve(ctx, c, M.SocksaddrFromNet(carrier.RemoteAddr()).Unwrap(), func(error) { carrier.Close() })
	if err == nil {
		select {
		case <-carrier.done:
		case <-s.ctx.Done():
		}
	}
}
func (s *Stream) serveHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.wg.Add(1)
	s.mu.Unlock()
	defer s.wg.Done()
	c := r.Context().Value(carrierKey{}).(*trackedConn)
	if r.Method != "GET" || r.URL.EscapedPath() != s.Spec.Transport.Path || (s.Spec.Transport.Host != "" && !strings.EqualFold(r.Host, s.Spec.Transport.Host)) || r.ContentLength > 0 || len(r.TransferEncoding) > 0 {
		w.Header().Set("Connection", "close")
		http.NotFound(w, r)
		return
	}
	if s.Spec.Transport.Type == "ws" {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true, CompressionMode: websocket.CompressionDisabled})
		if err != nil {
			return
		}
		defer ws.CloseNow()
		conn := websocket.NetConn(s.ctx, ws, websocket.MessageBinary)
		ws.SetReadLimit(1 << 20)
		s.serve(r.Context(), conn)
		return
	}
	if !headerToken(r.Header.Get("Connection"), "upgrade") || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		w.Header().Set("Connection", "close")
		http.Error(w, "invalid upgrade", http.StatusBadRequest)
		return
	}
	hijacked, rw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	if _, err = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n"); err == nil {
		err = rw.Flush()
	}
	if err != nil {
		c.Close()
		return
	}
	s.serve(r.Context(), &readerConn{Conn: hijacked, reader: rw.Reader})
}
func headerToken(v, want string) bool {
	for _, v := range strings.Split(v, ",") {
		if strings.EqualFold(strings.TrimSpace(v), want) {
			return true
		}
	}
	return false
}
func (s *Stream) close() {
	s.once.Do(func() {
		s.mu.Lock()
		s.closed = true
		if s.cancel != nil {
			s.cancel()
		}
		l, h := s.listener, s.http
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
			s.wg.Wait()
			if s.OnClose != nil {
				_ = s.OnClose()
			}
			s.events <- protocol.InstanceEvent{State: "stopped"}
			close(s.done)
		}()
	})
}
func (s *Stream) Stop(ctx context.Context) error {
	s.close()
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type carrierKey struct{}
type trackedConn struct {
	net.Conn
	raw      net.Conn
	server   *Stream
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
	server *Stream
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
type Bridge struct{ Handler protocol.RelayHandler }

func authenticated(ctx context.Context) {
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
