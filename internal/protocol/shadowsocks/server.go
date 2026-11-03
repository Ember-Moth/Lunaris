// SPDX-License-Identifier: GPL-3.0-only
package shadowsocks

import (
	"bytes"
	"context"
	"errors"
	"github.com/Ember-Moth/Lunaris/internal/authscan"
	"github.com/sagernet/sing/common/auth"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/ingress"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var ErrStopped = errors.New("Shadowsocks instance stopped")

// Server implements Shadowsocks framing, replay checks and UDP associations.
// Socket creation and carrier lifetime belong to the selected transport factory.
type Server struct {
	limits      model.Limits
	handler     protocol.RelayHandler
	method      *shadowaead.Method
	users       []compiledUser
	tcpScan     *authscan.Selector[netip.Addr]
	udpScan     *authscan.Selector[netip.AddrPort]
	saltSize    int
	replay      saltWindow
	mu          sync.Mutex
	stopped     bool
	ctx         context.Context
	udp         net.PacketConn
	sessions    map[packetSessionKey]*packetSession
	wg          sync.WaitGroup
	stopOnce    sync.Once
	done        chan struct{}
	writeMu     sync.Mutex
	queueMu     sync.Mutex
	queuedBytes int
}

func newServer(limits model.Limits, handler protocol.RelayHandler, method *shadowaead.Method) *Server {
	return &Server{limits: limits, handler: handler, method: method, sessions: make(map[packetSessionKey]*packetSession), done: make(chan struct{})}
}
func (s *Server) ServePacket(ctx context.Context, conn net.PacketConn) error {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return net.ErrClosed
	}
	s.ctx, s.udp = ctx, conn
	s.mu.Unlock()
	return s.readUDP()
}
func (s *Server) ClosePacket(ctx context.Context) error {
	s.stopOnce.Do(func() {
		s.mu.Lock()
		s.stopped = true
		sessions := make([]*packetSession, 0, len(s.sessions))
		for _, session := range s.sessions {
			sessions = append(sessions, session)
		}
		s.mu.Unlock()
		for _, session := range sessions {
			session.Close()
		}
		go func() { s.wg.Wait(); close(s.done) }()
	})
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type handshakeKey struct{}

func (s *Server) ServeStream(ctx context.Context, c net.Conn, src M.Socksaddr, onClose N.CloseHandlerFunc) error {
	header := make([]byte, s.saltSize+18)
	if _, err := io.ReadFull(c, header); err != nil {
		return err
	}
	match, err := s.tcpScan.Find(ingress.PeerIP(ctx, c.RemoteAddr()), len(s.users), func(index int) bool {
		return s.users[index].checkHeader(header[:s.saltSize], header[s.saltSize:])
	})
	if err != nil {
		return err
	}
	captured := &saltConn{Conn: authscan.ReplayPrefix(c, header), size: s.saltSize, match: match, user: match.Index}
	ctx = context.WithValue(ctx, handshakeKey{}, captured)
	ctx = auth.ContextWithUser(ctx, s.users[match.Index].ref)
	err = s.users[match.Index].service.NewConnection(ctx, captured, M.Metadata{Source: src})
	if authscan.Rejected(err) {
		match.Reject()
	}

	if onClose != nil {
		onClose(err)
	}
	return err
}

func (s *Server) NewConnection(ctx context.Context, connection net.Conn, metadata M.Metadata) error {
	state, ok := ctx.Value(handshakeKey{}).(*saltConn)
	if !ok || state.count != s.saltSize || !s.replay.accept(s.replayKey(state.user, state.salt[:state.count])) {
		return errors.New("replayed or invalid Shadowsocks handshake")
	}
	state.match.Accept()
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
	match       *authscan.Match[netip.Addr]
	user        int
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

func (s *Server) readUDP() error {
	for {
		buffer := buf.NewSize(65535)
		n, remote, local, err := ingress.ReadPacket(s.udp, buffer.FreeBytes())
		if err != nil {
			buffer.Release()
			return err
		}
		buffer.Truncate(n)
		if n < s.saltSize+16 {
			buffer.Release()
			continue
		}
		var salt [32]byte
		copy(salt[:], buffer.To(s.saltSize))
		// Each candidate gets the original ciphertext; AEAD failure may overwrite
		// its destination buffer. Keep the receive copy separate from decoder output.
		packet := bytes.Clone(buffer.Bytes())
		source := M.SocksaddrFromNet(remote).Unwrap().AddrPort()
		localEndpoint := M.SocksaddrFromNet(local).Unwrap().AddrPort()
		var destination M.Socksaddr
		match, err := s.udpScan.Find(source, len(s.users), func(index int) bool {
			buffer.Resize(0, 0)
			decoder := s.users[index].method.DialPacketConn(&datagramConn{packet: packet})
			var decodeErr error
			destination, decodeErr = decoder.ReadPacket(buffer)
			return decodeErr == nil && destination.Port != 0
		})
		if err != nil {
			buffer.Release()
			continue
		}
		if !s.replay.accept(s.replayKey(match.Index, salt[:s.saltSize])) {
			match.Reject()
			buffer.Release()
			continue
		}
		match.Accept()
		key := packetSessionKey{source: source, local: localEndpoint, user: match.Index}
		s.mu.Lock()
		if s.stopped {
			s.mu.Unlock()
			buffer.Release()
			return nil
		}
		session := s.sessions[key]
		created := false
		if session == nil {
			if len(s.sessions) >= s.limits.MaxUDPSessions {
				s.mu.Unlock()
				buffer.Release()
				continue
			}
			session = newPacketSession(s, source, localEndpoint)
			session.user = match.Index
			session.method = s.users[match.Index].method
			s.sessions[key] = session
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
			s.handler.NewPacketConnectionEx(auth.ContextWithUser(ingress.WithLocal(s.ctx, local), s.users[match.Index].ref), session, M.SocksaddrFromNetIP(source), destination, N.OnceClose(func(error) { session.Close(); s.wg.Done() }))
		}
	}
}
