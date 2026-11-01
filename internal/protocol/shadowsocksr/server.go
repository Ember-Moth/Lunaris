// SPDX-License-Identifier: GPL-3.0-only
package shadowsocksr

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	wire "github.com/Ember-Moth/Lunaris/internal/protocol/shadowsocksr/wire"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type server struct {
	service               *wire.Server
	codec                 *wire.PacketCodec
	identities            map[[4]byte]string
	limits                model.Limits
	handler               protocol.RelayHandler
	mu, writeMu, budgetMu sync.Mutex
	socket                net.PacketConn
	stopped               bool
	sessions              map[packetKey]*packetConn
	queued                int
	wg                    sync.WaitGroup
	once                  sync.Once
	done                  chan struct{}
}
type packetKey struct {
	user   [4]byte
	source netip.AddrPort
}

func (s *server) serveStream(ctx context.Context, raw net.Conn, source M.Socksaddr, close N.CloseHandlerFunc) error {
	c, err := s.service.WrapConn(raw)
	if err != nil {
		return err
	}
	dst, err := M.SocksaddrSerializer.ReadAddrPort(c)
	if err != nil {
		c.Close()
		return err
	}
	id, ok := c.UserID()
	identity, known := s.identities[id]
	if !ok || !known {
		c.Close()
		return errors.New("unknown authenticated ShadowsocksR user")
	}
	s.handler.NewConnectionEx(auth.ContextWithUser(ctx, identity), c, source, dst.Unwrap(), close)
	return nil
}
func (s *server) servePacket(ctx context.Context, c net.PacketConn) error {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return net.ErrClosed
	}
	s.socket = c
	s.mu.Unlock()
	for {
		b := buf.NewSize(65535)
		n, addr, err := c.ReadFrom(b.FreeBytes())
		if err != nil {
			b.Release()
			return err
		}
		b.Truncate(n)
		id, err := s.codec.Decode(b)
		if err != nil {
			b.Release()
			continue
		}
		dst, err := M.SocksaddrSerializer.ReadAddrPort(b)
		identity, ok := s.identities[id]
		if err != nil || !ok || !dst.IsValid() || dst.Port == 0 {
			b.Release()
			continue
		}
		source := M.SocksaddrFromNet(addr).Unwrap()
		key := packetKey{user: id, source: source.AddrPort()}
		s.mu.Lock()
		if s.stopped {
			s.mu.Unlock()
			b.Release()
			return net.ErrClosed
		}
		session := s.sessions[key]
		fresh := false
		if session == nil {
			if len(s.sessions) >= s.limits.MaxUDPSessions {
				s.mu.Unlock()
				b.Release()
				continue
			}
			session = newPacketConn(s, key)
			s.sessions[key] = session
			s.wg.Add(1)
			fresh = true
		}
		s.mu.Unlock()
		small := buf.NewSize(b.Len())
		_, _ = small.Write(b.Bytes())
		b.Release()
		session.deliver(small, dst.Unwrap())
		if fresh {
			s.handler.NewPacketConnectionEx(auth.ContextWithUser(ctx, identity), session, source, dst.Unwrap(), N.OnceClose(func(error) { session.Close(); s.wg.Done() }))
		}
	}
}
func (s *server) closePacket(ctx context.Context) error {
	s.once.Do(func() {
		s.mu.Lock()
		s.stopped = true
		cs := make([]*packetConn, 0, len(s.sessions))
		for _, c := range s.sessions {
			cs = append(cs, c)
		}
		s.mu.Unlock()
		for _, c := range cs {
			c.Close()
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
func (s *server) reserve(n int) bool {
	s.budgetMu.Lock()
	defer s.budgetMu.Unlock()
	if s.queued+n > 16<<20 {
		return false
	}
	s.queued += n
	return true
}
func (s *server) release(n int) { s.budgetMu.Lock(); s.queued -= n; s.budgetMu.Unlock() }
func (s *server) write(b *buf.Buffer, to netip.AddrPort) error {
	defer b.Release()
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.socket.SetWriteDeadline(time.Now().Add(s.limits.DialTimeout)); err != nil {
		return err
	}
	_, err := s.socket.WriteTo(b.Bytes(), net.UDPAddrFromAddrPort(to))
	return err
}
