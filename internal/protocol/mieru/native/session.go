// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package native

import (
	"context"
	"github.com/sagernet/sing/common/pipe"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type session struct {
	delivery   sync.Mutex
	readNotify chan struct{}
	id         uint32
	slot       bool
	ctx        context.Context
	cancel     context.CancelFunc
	userName   string
	underlay   *streamUnderlay

	incoming     chan []byte
	closed       chan struct{}
	once         sync.Once
	readMu       sync.Mutex
	writeMu      sync.Mutex
	remain       []byte
	nextSend     atomic.Uint32
	readDeadline pipe.Deadline
	writeDL      atomic.Int64
}

func newStreamSession(id uint32, userName string, underlay *streamUnderlay) *session {
	parent := underlay.ctx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	return &session{ctx: ctx, cancel: cancel, id: id, userName: userName, underlay: underlay, readNotify: make(chan struct{}, 1), incoming: make(chan []byte, max(1, underlay.server.option.QueueSize)), readDeadline: pipe.MakeDeadline(), closed: make(chan struct{})}
}

func (s *session) Read(dst []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if len(dst) == 0 {
		return 0, nil
	}
	if len(s.remain) != 0 {
		n := copy(dst, s.remain)
		s.remain = s.remain[n:]
		return n, nil
	}
	select {
	case payload := <-s.incoming:
		s.underlay.server.releaseBytes(len(payload))
		select {
		case s.readNotify <- struct{}{}:
		default:
		}
		n := copy(dst, payload)
		s.remain = payload[n:]
		return n, nil
	case <-s.closed:
		select {
		case payload := <-s.incoming:
			s.underlay.server.releaseBytes(len(payload))
			select {
			case s.readNotify <- struct{}{}:
			default:
			}
			n := copy(dst, payload)
			s.remain = payload[n:]
			return n, nil
		default:
			return 0, io.EOF
		}
	case <-s.readDeadline.Wait():
		return 0, os.ErrDeadlineExceeded
	}
}

func (s *session) Write(src []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	select {
	case <-s.closed:
		return 0, net.ErrClosed
	default:
	}
	if deadline := s.writeDL.Load(); deadline != 0 && time.Now().UnixNano() >= deadline {
		return 0, os.ErrDeadlineExceeded
	}
	written := 0
	for len(src) != 0 {
		length := min(len(src), maxPDU)
		meta := metadata{protocol: dataServerToClient, sessionID: s.id, seq: s.nextSend.Add(1) - 1,
			windowSize: 4096, payloadLen: uint16(length)}
		if err := s.underlay.writeSegment(meta, src[:length]); err != nil {
			return written, err
		}
		written += length
		src = src[length:]
	}
	return written, nil
}

func (s *session) Close() error {
	s.once.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		meta := metadata{protocol: closeSessionRequest, sessionID: s.id, seq: s.nextSend.Add(1) - 1}
		_ = s.underlay.writeSegment(meta, nil)
		s.closeBuffers()
		s.underlay.sessions.CompareAndDelete(s.id, s)
		if s.slot {
			s.underlay.server.releaseSession()
		}
	})
	return nil
}

func (s *session) closeRemote() {
	s.once.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		s.closeBuffers()
		s.underlay.sessions.CompareAndDelete(s.id, s)
		if s.slot {
			s.underlay.server.releaseSession()
		}
	})
}

func (s *session) deliver(payload []byte) bool {
	if len(payload) == 0 {
		return true
	}
	if !s.underlay.server.waitBytes(s.ctx, len(payload)) {
		return false
	}
	for {
		s.delivery.Lock()
		select {
		case <-s.closed:
			s.delivery.Unlock()
			s.underlay.server.releaseBytes(len(payload))
			return false
		default:
		}
		select {
		case s.incoming <- payload:
			s.delivery.Unlock()
			return true
		default:
			s.delivery.Unlock()
		}
		select {
		case <-s.readNotify:
		case <-s.closed:
			s.underlay.server.releaseBytes(len(payload))
			return false
		case <-s.ctx.Done():
			s.underlay.server.releaseBytes(len(payload))
			return false
		}
	}
}
func (s *session) closeBuffers() {
	s.delivery.Lock()
	defer s.delivery.Unlock()
	s.readDeadline.Set(time.Time{})
	close(s.closed)
	for {
		select {
		case p := <-s.incoming:
			s.underlay.server.releaseBytes(len(p))
		default:
			return
		}
	}
}

func (s *session) LocalAddr() net.Addr  { return s.underlay.conn.LocalAddr() }
func (s *session) RemoteAddr() net.Addr { return s.underlay.conn.RemoteAddr() }

func (s *session) SetDeadline(deadline time.Time) error {
	_ = s.SetReadDeadline(deadline)
	return s.SetWriteDeadline(deadline)
}

func (s *session) SetReadDeadline(deadline time.Time) error { s.readDeadline.Set(deadline); return nil }

func (s *session) SetWriteDeadline(deadline time.Time) error {
	if deadline.IsZero() {
		s.writeDL.Store(0)
	} else {
		s.writeDL.Store(deadline.UnixNano())
	}
	return nil
}

func (s *session) UserName() string { return s.userName }

var _ net.Conn = (*session)(nil)

func (s *session) Context() context.Context { return s.ctx }
func (s *session) Authenticated()           { s.underlay.authenticated.Store(true) }
