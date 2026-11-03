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

const (
	packetWindow        = 4096
	packetInitialRTO    = 2 * time.Second
	packetMinimumRTO    = 100 * time.Millisecond
	packetIdleTimeout   = 15 * time.Second
	packetMaxRetransmit = 20
)

type packetOutbound struct {
	meta     metadata
	payload  []byte
	sentAt   time.Time
	timeout  time.Duration
	attempts int
}

type packetSession struct {
	delivery    sync.Mutex
	ctx         context.Context
	cancel      context.CancelFunc
	id          uint32
	slot        bool
	userName    string
	user        *compiledUser
	aead        cipherAEAD
	server      *Server
	remote      net.Addr
	remoteKey   packetRemoteKey
	local       net.Addr
	mtu         int
	remoteState *remoteCipher

	incoming     chan []byte
	closed       chan struct{}
	once         sync.Once
	readMu       sync.Mutex
	writeMu      sync.Mutex
	stateMu      sync.Mutex
	remain       []byte
	recvBuf      map[uint32]segment
	inflight     map[uint32]*packetOutbound
	nextRecv     uint32
	nextSend     uint32
	oldestSend   uint32
	lastSeen     time.Time
	lastTX       time.Time
	nextRetry    time.Time
	readDeadline pipe.Deadline
	writeDL      atomic.Int64
	ackQueued    atomic.Bool
	windowWake   chan struct{}
	cwnd         float64
	remoteWindow uint32
	smoothedRTT  time.Duration
	rttDeviation time.Duration
}

func newPacketSession(id uint32, match userMatch, server *Server, remote, local net.Addr, mtu int, state *remoteCipher) *packetSession {
	parent := server.ctx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	return &packetSession{ctx: ctx, cancel: cancel, id: id, userName: match.user.name, user: match.user, aead: match.aead, server: server,
		remote: remote, local: local, mtu: mtu, remoteState: state, incoming: make(chan []byte, max(1, server.option.QueueSize)), readDeadline: pipe.MakeDeadline(), closed: make(chan struct{}),
		remoteKey: remoteKeyFrom(remote),
		recvBuf:   make(map[uint32]segment), inflight: make(map[uint32]*packetOutbound), lastSeen: time.Now(), lastTX: time.Now(),
		windowWake: make(chan struct{}, 1), cwnd: 16, remoteWindow: 16}
}

func (s *packetSession) Read(dst []byte) (int, error) {
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
		s.server.releaseBytes(len(payload))
		s.flushReceive()
		n := copy(dst, payload)
		s.remain = payload[n:]
		return n, nil
	case <-s.closed:
		select {
		case payload := <-s.incoming:
			s.server.releaseBytes(len(payload))
			s.flushReceive()
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

func (s *packetSession) Write(src []byte) (int, error) {
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
	fragmentSize := min(maxPDU, max(1, s.mtu-packetOverhead))
	written := 0
	for len(src) != 0 {
		chunkSize := min(len(src), maxPDU)
		chunk := src[:chunkSize]
		fragments := (chunkSize + fragmentSize - 1) / fragmentSize
		for index := fragments - 1; index >= 0; index-- {
			length := min(len(chunk), fragmentSize)
			part := append([]byte(nil), chunk[:length]...)
			meta := s.nextOutbound(dataServerToClient, len(part))
			meta.fragment = byte(index)
			if err := s.sendReliable(meta, part); err != nil {
				return written, err
			}
			chunk = chunk[length:]
		}
		written += chunkSize
		src = src[chunkSize:]
	}
	return written, nil
}

func (s *packetSession) nextOutbound(kind protocolType, payloadLength int) metadata {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	meta := metadata{protocol: kind, sessionID: s.id, seq: s.nextSend, unAckSeq: s.nextRecv,
		windowSize: uint16(max(0, s.receiveWindowLocked())), payloadLen: uint16(payloadLength)}
	s.nextSend++
	return meta
}

func (s *packetSession) sendReliable(meta metadata, payload []byte) error {
	for {
		s.stateMu.Lock()
		limit := min(int(s.cwnd), int(s.remoteWindow))
		ready := meta.sessionProtocol() || (limit > 0 && len(s.inflight) < limit)
		s.stateMu.Unlock()
		if ready {
			break
		}
		var timeout <-chan time.Time
		var timer *time.Timer
		if deadline := s.writeDL.Load(); deadline != 0 {
			duration := time.Until(time.Unix(0, deadline))
			if duration <= 0 {
				return os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(duration)
			timeout = timer.C
		}
		select {
		case <-s.windowWake:
		case <-s.closed:
			if timer != nil {
				timer.Stop()
			}
			return net.ErrClosed
		case <-timeout:
			return os.ErrDeadlineExceeded
		}
		if timer != nil {
			timer.Stop()
		}
	}
	s.stateMu.Lock()
	timeout := s.retransmissionTimeoutLocked()
	s.stateMu.Unlock()
	if !s.server.waitBytes(s.ctx, len(payload)) {
		return net.ErrClosed
	}
	outbound := &packetOutbound{meta: meta, payload: payload, sentAt: time.Now(), timeout: timeout, attempts: 1}
	s.stateMu.Lock()
	if len(s.inflight) == 0 {
		s.oldestSend = meta.seq
	}
	select {
	case <-s.closed:
		s.stateMu.Unlock()
		s.server.releaseBytes(len(payload))
		return net.ErrClosed
	default:
	}
	s.inflight[meta.seq] = outbound
	s.lastTX = outbound.sentAt
	deadline := outbound.sentAt.Add(outbound.timeout)
	if s.nextRetry.IsZero() || deadline.Before(s.nextRetry) {
		s.nextRetry = deadline
	}
	s.stateMu.Unlock()
	return s.server.writePacket(meta, payload, s.aead, s.userName, s.remote, s.local)
}

func (s *packetSession) accept(seg segment) {
	s.stateMu.Lock()
	select {
	case <-s.closed:
		s.stateMu.Unlock()
		return
	default:
	}
	s.lastSeen = time.Now()
	acked := 0
	now := time.Now()
	removedNextRetry := false
	for count := len(s.inflight); count > 0 && sequenceBefore(s.oldestSend, seg.meta.unAckSeq); count-- {
		outbound, exists := s.inflight[s.oldestSend]
		delete(s.inflight, s.oldestSend)
		s.oldestSend++
		if !exists {
			continue
		}
		if len(outbound.payload) > 0 {
			s.server.releaseBytes(len(outbound.payload))
		}
		acked++
		if outbound.sentAt.Add(outbound.timeout).Equal(s.nextRetry) {
			removedNextRetry = true
		}
		if outbound.attempts == 1 {
			s.updateRTTLocked(now.Sub(outbound.sentAt))
		}
	}
	if len(s.inflight) == 0 {
		s.nextRetry = time.Time{}
	} else if removedNextRetry {
		s.updateNextRetryLocked()
	}
	if acked != 0 {
		s.cwnd = min(float64(s.window()), s.cwnd+float64(acked)/s.cwnd)
		select {
		case s.windowWake <- struct{}{}:
		default:
		}
	}
	if seg.meta.dataProtocol() {
		s.remoteWindow = uint32(seg.meta.windowSize)
	}
	if seg.meta.protocol == ackClientToServer {
		s.stateMu.Unlock()
		return
	}
	if seg.meta.seq >= s.nextRecv && seg.meta.seq-s.nextRecv < uint32(s.window()) {
		if _, exists := s.recvBuf[seg.meta.seq]; !exists && s.server.reserveBytes(len(seg.payload)) {
			s.recvBuf[seg.meta.seq] = seg
		}
	}
	s.stateMu.Unlock()
	s.flushReceive()
}
func (s *packetSession) window() int {
	if s.server == nil {
		return packetWindow
	}
	return min(packetWindow, max(32, 4*s.server.option.QueueSize))
}
func (s *packetSession) receiveWindowLocked() int {
	return max(0, s.window()-len(s.recvBuf)-len(s.incoming))
}
func (s *packetSession) flushReceive() {
	s.delivery.Lock()
	s.stateMu.Lock()
	select {
	case <-s.closed:
		s.stateMu.Unlock()
		s.delivery.Unlock()
		return
	default:
	}
	for {
		seg, ok := s.recvBuf[s.nextRecv]
		if !ok || (len(seg.payload) > 0 && len(s.incoming) == cap(s.incoming)) {
			break
		}
		delete(s.recvBuf, s.nextRecv)
		s.nextRecv++
		if len(seg.payload) > 0 {
			s.incoming <- seg.payload
		}
	}
	s.stateMu.Unlock()
	s.delivery.Unlock()
	s.server.scheduleAck(s)
}
func (s *packetSession) closeBuffers() {
	s.delivery.Lock()
	defer s.delivery.Unlock()
	s.readDeadline.Set(time.Time{})
	close(s.closed)
	s.stateMu.Lock()
	for _, seg := range s.recvBuf {
		s.server.releaseBytes(len(seg.payload))
	}
	clear(s.recvBuf)
	for _, sent := range s.inflight {
		s.server.releaseBytes(len(sent.payload))
	}
	clear(s.inflight)
	s.stateMu.Unlock()
	for {
		select {
		case payload := <-s.incoming:
			s.server.releaseBytes(len(payload))
		default:
			return
		}
	}
}

func (s *packetSession) updateRTTLocked(sample time.Duration) {
	if sample <= 0 {
		return
	}
	if s.smoothedRTT == 0 {
		s.smoothedRTT = sample
		s.rttDeviation = sample / 2
		return
	}
	delta := s.smoothedRTT - sample
	if delta < 0 {
		delta = -delta
	}
	s.rttDeviation = (3*s.rttDeviation + delta) / 4
	s.smoothedRTT = (7*s.smoothedRTT + sample) / 8
}

func (s *packetSession) retransmissionTimeoutLocked() time.Duration {
	if s.smoothedRTT == 0 {
		return packetInitialRTO
	}
	return max(packetMinimumRTO, (s.smoothedRTT+4*s.rttDeviation+time.Millisecond)*3/2)
}

func (s *packetSession) sendAck() {
	s.stateMu.Lock()
	ack := metadata{protocol: ackServerToClient, sessionID: s.id, seq: lastSequence(s.nextSend),
		unAckSeq: s.nextRecv, windowSize: uint16(max(0, s.receiveWindowLocked()))}
	s.lastTX = time.Now()
	s.stateMu.Unlock()
	_ = s.server.writePacket(ack, nil, s.aead, s.userName, s.remote, s.local)
}

func (s *packetSession) maintain(now time.Time) bool {
	s.stateMu.Lock()
	if now.Sub(s.lastSeen) >= packetIdleTimeout {
		s.stateMu.Unlock()
		_ = s.Close()
		return false
	}
	var resend []*packetOutbound
	if !s.nextRetry.IsZero() && !now.Before(s.nextRetry) {
		for _, outbound := range s.inflight {
			if now.Sub(outbound.sentAt) < outbound.timeout {
				continue
			}
			if outbound.attempts >= packetMaxRetransmit {
				s.stateMu.Unlock()
				_ = s.Close()
				return false
			}
			outbound.attempts++
			s.cwnd = max(16, s.cwnd/2)
			outbound.sentAt = now
			outbound.timeout = min(10*time.Second, outbound.timeout+outbound.timeout/2)
			outbound.meta.unAckSeq = s.nextRecv
			resend = append(resend, outbound)
		}
		s.updateNextRetryLocked()
	}
	if now.Sub(s.lastTX) >= 5*time.Second {
		ack := &packetOutbound{meta: metadata{protocol: ackServerToClient, sessionID: s.id,
			seq: lastSequence(s.nextSend), unAckSeq: s.nextRecv, windowSize: uint16(max(0, s.receiveWindowLocked()))}}
		resend = append(resend, ack)
		s.lastTX = now
	}
	s.stateMu.Unlock()
	for _, outbound := range resend {
		_ = s.server.writePacket(outbound.meta, outbound.payload, s.aead, s.userName, s.remote, s.local)
	}
	return true
}

func (s *packetSession) updateNextRetryLocked() {
	s.nextRetry = time.Time{}
	for _, outbound := range s.inflight {
		deadline := outbound.sentAt.Add(outbound.timeout)
		if s.nextRetry.IsZero() || deadline.Before(s.nextRetry) {
			s.nextRetry = deadline
		}
	}
}

func (s *packetSession) Close() error {
	s.once.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		meta := s.nextOutbound(closeSessionRequest, 0)
		_ = s.server.writePacket(meta, nil, s.aead, s.userName, s.remote, s.local)
		s.closeBuffers()
		s.server.packetSessions.CompareAndDelete(packetSessionKey{credential: s.user.credential, remote: s.remoteKey, local: remoteKeyFrom(s.local), id: s.id}, s)
		s.releaseRemoteState()
		if s.slot {
			s.server.releaseSession()
		}
	})
	return nil
}

func (s *packetSession) closeRemote() {
	s.once.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		s.closeBuffers()
		s.server.packetSessions.CompareAndDelete(packetSessionKey{credential: s.user.credential, remote: s.remoteKey, local: remoteKeyFrom(s.local), id: s.id}, s)
		s.releaseRemoteState()
		if s.slot {
			s.server.releaseSession()
		}
	})
}

func (s *packetSession) releaseRemoteState() {
	state := s.remoteState
	if state == nil {
		return
	}
	s.remoteState = nil
	s.server.releaseRemoteCipher(state)
}

func (s *packetSession) LocalAddr() net.Addr  { return s.local }
func (s *packetSession) RemoteAddr() net.Addr { return s.remote }

func (s *packetSession) SetDeadline(deadline time.Time) error {
	_ = s.SetReadDeadline(deadline)
	return s.SetWriteDeadline(deadline)
}
func (s *packetSession) SetReadDeadline(deadline time.Time) error {
	s.readDeadline.Set(deadline)
	return nil
}

func (s *packetSession) SetWriteDeadline(deadline time.Time) error {
	if deadline.IsZero() {
		s.writeDL.Store(0)
	} else {
		s.writeDL.Store(deadline.UnixNano())
	}
	return nil
}
func (s *packetSession) UserName() string { return s.userName }

func lastSequence(next uint32) uint32 {
	if next == 0 {
		return 0
	}
	return next - 1
}

func sequenceBefore(sequence, next uint32) bool {
	return int32(sequence-next) < 0
}

var _ net.Conn = (*packetSession)(nil)

func (s *packetSession) Context() context.Context { return s.ctx }
