// SPDX-License-Identifier: GPL-3.0-only
package shadowsocks

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	SS "github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var ErrStopped = errors.New("Shadowsocks instance stopped")

// Server owns network resources; the upstream module only performs protocol I/O.
type Server struct {
	spec             model.ListenerSpec
	limits           model.Limits
	handler          protocol.RelayHandler
	method           *shadowaead.Method
	service          SS.Service
	saltSize         int
	replay           saltWindow
	mu               sync.Mutex
	started, stopped bool
	ctx              context.Context
	cancel           context.CancelFunc
	stopParent       func() bool
	tcp              net.Listener
	udp              *net.UDPConn
	connections      map[net.Conn]struct{}
	sessions         map[netip.AddrPort]*packetSession
	pending          chan struct{}
	wg               sync.WaitGroup
	stopOnce         sync.Once
	failOnce         sync.Once
	done             chan struct{}
	events           chan protocol.InstanceEvent
	writeMu          sync.Mutex
	queueMu          sync.Mutex
	queuedBytes      int
}

func newServer(spec model.ListenerSpec, limits model.Limits, handler protocol.RelayHandler, method *shadowaead.Method) *Server {
	return &Server{spec: spec, limits: limits, handler: handler, method: method,
		connections: make(map[net.Conn]struct{}), sessions: make(map[netip.AddrPort]*packetSession),
		pending: make(chan struct{}, limits.MaxPendingHandshakes), done: make(chan struct{}), events: make(chan protocol.InstanceEvent, 4)}
}

func (s *Server) Start(parent context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started || s.stopped {
		return errors.New("Shadowsocks instance cannot be started twice")
	}
	if err := parent.Err(); err != nil {
		return err
	}
	s.started = true
	s.ctx, s.cancel = context.WithCancel(parent)
	networks := s.spec.Network
	if len(networks) == 0 {
		networks = []string{"tcp", "udp"}
	}
	address := net.JoinHostPort(s.spec.Address, strconv.Itoa(int(s.spec.Port)))
	var err error
	if slices.Contains(networks, "tcp") {
		s.tcp, err = (&net.ListenConfig{}).Listen(s.ctx, "tcp", address)
		if err != nil {
			s.cancel()
			return err
		}
		// Port zero is only used by programmatic tests, never accepted in node YAML.
		if s.spec.Port == 0 {
			address = s.tcp.Addr().String()
		}
	}
	if slices.Contains(networks, "udp") {
		udpAddress, resolveErr := net.ResolveUDPAddr("udp", address)
		if resolveErr != nil {
			err = resolveErr
		} else {
			s.udp, err = net.ListenUDP("udp", udpAddress)
		}
		if err != nil {
			if s.tcp != nil {
				s.tcp.Close()
			}
			s.cancel()
			return err
		}
	}
	if s.tcp == nil && s.udp == nil {
		s.cancel()
		return errors.New("listener requires tcp or udp")
	}
	if s.tcp != nil {
		s.wg.Add(1)
		go s.acceptTCP()
	}
	if s.udp != nil {
		s.wg.Add(1)
		go s.readUDP()
	}
	s.stopParent = context.AfterFunc(s.ctx, s.initiateClose)
	s.events <- protocol.InstanceEvent{State: "running"}
	return nil
}

func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tcp != nil {
		return s.tcp.Addr()
	}
	if s.udp != nil {
		return s.udp.LocalAddr()
	}
	return nil
}

func (s *Server) Events() <-chan protocol.InstanceEvent { return s.events }

func (s *Server) fail(err error) {
	s.mu.Lock()
	stopping := s.stopped || s.ctx.Err() != nil
	s.mu.Unlock()
	if stopping {
		return
	}
	s.failOnce.Do(func() { s.events <- protocol.InstanceEvent{State: "failed", Err: err}; s.initiateClose() })
}

func (s *Server) initiateClose() {
	s.stopOnce.Do(func() {
		s.mu.Lock()
		s.stopped = true
		if s.cancel != nil {
			s.cancel()
		}
		if s.stopParent != nil {
			s.stopParent()
		}
		connections := make([]net.Conn, 0, len(s.connections))
		for connection := range s.connections {
			connections = append(connections, connection)
		}
		sessions := make([]*packetSession, 0, len(s.sessions))
		for _, session := range s.sessions {
			sessions = append(sessions, session)
		}
		tcp, udp := s.tcp, s.udp
		s.mu.Unlock()
		if tcp != nil {
			tcp.Close()
		}
		if udp != nil {
			udp.Close()
		}
		for _, connection := range connections {
			connection.Close()
		}
		for _, session := range sessions {
			session.Close()
		}
		go func() { s.wg.Wait(); s.events <- protocol.InstanceEvent{State: "stopped"}; close(s.done) }()
	})
}

func (s *Server) Stop(ctx context.Context) error {
	s.initiateClose()
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type handshakeKey struct{}
type handshake struct {
	connection *saltConn
	release    func()
}

func (s *Server) acceptTCP() {
	defer s.wg.Done()
	for {
		connection, err := s.tcp.Accept()
		if err != nil {
			s.fail(err)
			return
		}
		s.mu.Lock()
		if s.stopped || len(s.connections) >= s.limits.MaxConnections {
			s.mu.Unlock()
			connection.Close()
			continue
		}
		select {
		case s.pending <- struct{}{}:
		default:
			s.mu.Unlock()
			connection.Close()
			continue
		}
		s.connections[connection] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer connection.Close()
			defer func() { s.mu.Lock(); delete(s.connections, connection); s.mu.Unlock() }()
			release := sync.OnceFunc(func() { <-s.pending })
			defer release()
			if err := connection.SetReadDeadline(time.Now().Add(s.limits.HandshakeTimeout)); err != nil {
				return
			}
			captured := &saltConn{Conn: connection, size: s.saltSize}
			ctx := context.WithValue(s.ctx, handshakeKey{}, handshake{connection: captured, release: release})
			// A legacy handler owns this call until the shared relay reports completion.
			_ = s.service.NewConnection(ctx, captured, M.Metadata{Source: M.SocksaddrFromNet(connection.RemoteAddr()).Unwrap()})
		}()
	}
}

func (s *Server) NewConnection(ctx context.Context, connection net.Conn, metadata M.Metadata) error {
	state, ok := ctx.Value(handshakeKey{}).(handshake)
	if !ok || !s.replay.accept(state.connection.salt[:state.connection.count]) {
		return errors.New("replayed or invalid Shadowsocks handshake")
	}
	if err := connection.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	state.release()
	done := make(chan error, 1)
	s.handler.NewConnectionEx(ctx, connection, metadata.Source, metadata.Destination, N.OnceClose(func(err error) { done <- err }))
	return <-done
}

// The legacy upstream UDP service is deliberately not used. UDP goes through
// bounded packetSession instances and the same sing UDP handler as other protocols.
func (s *Server) NewPacketConnection(context.Context, N.PacketConn, M.Metadata) error {
	return errors.New("unexpected legacy UDP callback")
}
func (s *Server) NewError(context.Context, error) {}

type saltConn struct {
	net.Conn
	salt        [32]byte
	size, count int
}

func (c *saltConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if c.count < c.size {
		c.count += copy(c.salt[c.count:c.size], p[:n])
	}
	return n, err
}
func (c *saltConn) Upstream() any     { return c.Conn }
func (c *saltConn) CloseRead() error  { return N.CloseRead(c.Conn) }
func (c *saltConn) CloseWrite() error { return N.CloseWrite(c.Conn) }

// Authenticated salts only: unauthenticated packets cannot fill this bounded
// window. Full windows reject new entries until old ones expire.
type saltWindow struct {
	mu      sync.Mutex
	entries map[string]time.Time
	cleaned time.Time
}

func (w *saltWindow) accept(salt []byte) bool {
	if len(salt) == 0 {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.entries == nil {
		w.entries = make(map[string]time.Time)
	}
	now := time.Now()
	if now.Sub(w.cleaned) >= time.Second {
		for key, expires := range w.entries {
			if !now.Before(expires) {
				delete(w.entries, key)
			}
		}
		w.cleaned = now
	}
	key := string(salt)
	if expires, exists := w.entries[key]; exists && now.Before(expires) {
		return false
	}
	if len(w.entries) >= 65536 {
		return false
	}
	w.entries[key] = now.Add(time.Minute)
	return true
}

func (s *Server) readUDP() {
	defer s.wg.Done()
	for {
		buffer := buf.NewSize(65535)
		n, source, err := s.udp.ReadFromUDPAddrPort(buffer.FreeBytes())
		if err != nil {
			buffer.Release()
			s.fail(err)
			return
		}
		buffer.Truncate(n)
		if n < s.saltSize+16 {
			buffer.Release()
			continue
		}
		var salt [32]byte
		copy(salt[:], buffer.To(s.saltSize))
		packet := buffer.Bytes()
		buffer.Truncate(0)
		decoder := s.method.DialPacketConn(&datagramConn{packet: packet})
		destination, err := decoder.ReadPacket(buffer)
		if err != nil || destination.Port == 0 || !s.replay.accept(salt[:s.saltSize]) {
			buffer.Release()
			continue
		}
		source = netip.AddrPortFrom(source.Addr().Unmap(), source.Port())
		s.mu.Lock()
		if s.stopped {
			s.mu.Unlock()
			buffer.Release()
			return
		}
		session := s.sessions[source]
		created := false
		if session == nil {
			if len(s.sessions) >= s.limits.MaxUDPSessions {
				s.mu.Unlock()
				buffer.Release()
				continue
			}
			session = newPacketSession(s, source)
			s.sessions[source] = session
			s.wg.Add(1)
			created = true
		}
		s.mu.Unlock()
		// Do not retain a 64 KiB receive allocation for every small queued packet.
		payload := buf.NewSize(buffer.Len())
		_, _ = payload.Write(buffer.Bytes())
		buffer.Release()
		session.offer(payload, destination)
		if created {
			s.handler.NewPacketConnectionEx(s.ctx, session, M.SocksaddrFromNetIP(source), destination, N.OnceClose(func(error) { session.Close(); s.wg.Done() }))
		}
	}
}
