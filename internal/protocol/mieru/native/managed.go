// SPDX-License-Identifier: GPL-3.0-only
package native

import (
	"context"
	"errors"
	"net"
	"time"
)

// StartManaged starts protocol workers without binding sockets. Lunaris's
// transport owns the TCP listener, UDP socket and carrier admission limits.
func (s *Server) StartManaged() error {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	if s.ctx.Err() != nil {
		return net.ErrClosed
	}
	s.managed = true
	s.startOnce.Do(func() { s.wg.Add(1); go s.acceptSessions() })
	return s.startErr
}
func (s *Server) ServeConnection(ctx context.Context, c net.Conn) error {
	s.lifecycle.Lock()
	if s.ctx.Err() != nil || ctx.Err() != nil {
		s.lifecycle.Unlock()
		return net.ErrClosed
	}
	ctx, cancel := context.WithCancel(ctx)
	u := &streamUnderlay{server: s, conn: c, done: make(chan struct{}), ctx: ctx, cancel: cancel, handshakeDeadline: time.Now().Add(s.option.HandshakeTimeout)}
	s.streams.Store(u, u)
	s.wg.Add(1)
	s.lifecycle.Unlock()
	defer s.wg.Done()
	defer s.streams.Delete(u)
	return u.run()
}
func (s *Server) ServePacket(ctx context.Context, c net.PacketConn) error {
	s.lifecycle.Lock()
	if s.ctx.Err() != nil || ctx.Err() != nil {
		s.lifecycle.Unlock()
		return net.ErrClosed
	}
	if s.packet != nil {
		s.lifecycle.Unlock()
		return errors.New("mieru UDP socket already attached")
	}
	s.packet = c
	s.wg.Add(3)
	go s.maintainPackets()
	go s.ackPackets()
	s.lifecycle.Unlock()
	s.listenPacket()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if s.ctx.Err() != nil {
		return nil
	}
	return net.ErrClosed
}
func (s *Server) reserveSession() bool {
	for {
		if s.ctx.Err() != nil {
			return false
		}
		current := s.sessionCount.Load()
		if current >= int64(s.option.MaxSessions) {
			return false
		}
		if s.sessionCount.CompareAndSwap(current, current+1) {
			return true
		}
	}
}
func (s *Server) releaseSession() { s.sessionCount.Add(-1) }
