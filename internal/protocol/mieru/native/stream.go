// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package native

import (
	"context"
	"errors"
	"github.com/Ember-Moth/Lunaris/internal/authscan"
	"github.com/Ember-Moth/Lunaris/internal/ingress"
	"io"
	"math"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

type streamUnderlay struct {
	server            *Server
	ctx               context.Context
	cancel            context.CancelFunc
	authenticated     atomic.Bool
	handshakeDeadline time.Time
	conn              net.Conn
	done              chan struct{}
	once              sync.Once

	user *compiledUser
	recv streamCipher
	send streamCipher

	writeMu         sync.Mutex
	sessions        sync.Map
	metadataScratch [metadataLength]byte
	recvScratch     [metadataLength]byte
}

func (u *streamUnderlay) run() error {
	defer u.close()
	for {
		seg, err := u.readSegment()
		if err != nil {
			return err
		}
		if err = u.dispatch(seg); err != nil {
			return err
		}
	}
}

func (u *streamUnderlay) readSegment() (_ segment, resultErr error) {
	var verdict *authscan.Match[netip.Addr]
	defer func() {
		if verdict != nil && authscan.Rejected(resultErr) {
			verdict.Reject()
		}
	}()
	first := u.recv.aead == nil
	if !u.authenticated.Load() {
		_ = u.conn.SetReadDeadline(u.handshakeDeadline)
	} else {
		_ = u.conn.SetReadDeadline(time.Now().Add(u.server.option.IdleTimeout))
	}
	length := metadataLength + authTagSize
	if first {
		length += nonceSize
	}
	var encryptedStorage [nonceSize + metadataLength + authTagSize]byte
	encrypted := encryptedStorage[:length]
	if _, err := io.ReadFull(u.conn, encrypted); err != nil {
		return segment{}, err
	}
	var plaintext []byte
	if first {
		snapshot := u.server.users.Load()
		match, err := snapshot.discover(encrypted, u.recvScratch[:0], &net.TCPAddr{IP: net.IP(ingress.PeerIP(u.ctx, u.conn.RemoteAddr()).AsSlice())})
		if err != nil {
			return segment{}, err
		}
		verdict = match.verdict
		u.user = match.user
		u.recv = streamCipher{aead: match.aead, set: true}
		copy(u.recv.nonce[:], encrypted[:nonceSize])
		plaintext = match.text
		u.send.aead = match.aead
	} else {
		var err error
		plaintext, err = u.recv.decrypt(u.recvScratch[:0], encrypted)
		if err != nil {
			return segment{}, err
		}
	}
	meta, err := parseMetadata(plaintext, time.Now())
	if err != nil {
		return segment{}, err
	}
	// The first record must be a client session opener. A server response uses
	// the same epoch key and can decrypt, but is not an authenticated handshake.
	if first && (meta.protocol != openSessionRequest || meta.sessionID == 0) {
		return segment{}, errors.New("mieru: invalid initial client protocol")
	}
	if meta.prefixLen != 0 {
		if _, err = io.CopyN(io.Discard, u.conn, int64(meta.prefixLen)); err != nil {
			return segment{}, err
		}
	}
	var payload []byte
	if meta.payloadLen != 0 {
		payload = make([]byte, int(meta.payloadLen)+authTagSize)
		if _, err = io.ReadFull(u.conn, payload); err != nil {
			return segment{}, err
		}
		payload, err = u.recv.decrypt(payload[:0], payload)
		if err != nil {
			return segment{}, err
		}
	}
	if meta.suffixLen != 0 {
		if _, err = io.CopyN(io.Discard, u.conn, int64(meta.suffixLen)); err != nil {
			return segment{}, err
		}
	}
	if first {
		if !u.server.users.Load().active(u.user) {
			return segment{}, errors.New("mieru: inactive credential")
		}
		if u.server.replay.seen(u.user.credential, encrypted[:nonceSize]) {
			return segment{}, errors.New("mieru: replayed stream handshake")
		}
		verdict.Accept()
		u.authenticated.Store(true)
		if u.server.option.OnAuthenticated != nil {
			u.server.option.OnAuthenticated(u.ctx)
		}
	}
	return segment{meta: meta, payload: payload}, nil
}

func (u *streamUnderlay) dispatch(seg segment) error {
	meta := seg.meta
	switch meta.protocol {
	case openSessionRequest:
		if meta.sessionID == 0 {
			return errors.New("mieru: reserved session ID")
		}
		if _, loaded := u.sessions.Load(meta.sessionID); loaded {
			return nil
		}
		if !u.server.users.Load().active(u.user) {
			return u.writeSegment(metadata{protocol: closeSessionRequest, sessionID: meta.sessionID, status: 1}, nil)
		}
		if !u.server.reserveSession() {
			return u.writeSegment(metadata{protocol: closeSessionRequest, sessionID: meta.sessionID, status: 1}, nil)
		}
		streamSession := newStreamSession(meta.sessionID, u.user.name, u)
		streamSession.slot = true
		if actual, loaded := u.sessions.LoadOrStore(meta.sessionID, streamSession); loaded {
			streamSession.slot = false
			u.server.releaseSession()
			streamSession = actual.(*session)
		}
		if u.ctx.Err() != nil {
			streamSession.closeRemote()
			return net.ErrClosed
		}
		if !streamSession.deliver(seg.payload) {
			return net.ErrClosed
		}
		response := metadata{protocol: openSessionResponse, sessionID: meta.sessionID, seq: streamSession.nextSend.Add(1) - 1}
		if err := u.writeSegment(response, nil); err != nil {
			return err
		}
		select {
		case u.server.accepted <- streamSession:
			return nil
		case <-u.done:
			return net.ErrClosed
		case <-u.server.ctx.Done():
			return net.ErrClosed
		}
	case dataClientToServer:
		value, loaded := u.sessions.Load(meta.sessionID)
		if !loaded {
			return u.writeSegment(metadata{protocol: closeSessionRequest, sessionID: meta.sessionID, seq: meta.unAckSeq}, nil)
		}
		value.(*session).deliver(seg.payload)
		return nil
	case ackClientToServer:
		return nil
	case closeSessionRequest:
		if value, loaded := u.sessions.Load(meta.sessionID); loaded {
			value.(*session).closeRemote()
		}
		return u.writeSegment(metadata{protocol: closeSessionResponse, sessionID: meta.sessionID, seq: meta.seq}, nil)
	case closeSessionResponse:
		if value, loaded := u.sessions.Load(meta.sessionID); loaded {
			value.(*session).closeRemote()
		}
		return nil
	default:
		return errors.New("mieru: invalid client protocol")
	}
}

func (u *streamUnderlay) writeSegment(meta metadata, payload []byte) error {
	u.writeMu.Lock()
	defer u.writeMu.Unlock()
	select {
	case <-u.done:
		return net.ErrClosed
	default:
	}
	_ = u.conn.SetWriteDeadline(time.Now().Add(u.server.option.WriteTimeout))
	meta.payloadLen = uint16(len(payload))
	pattern := u.server.pattern
	middleLength := 0
	if meta.dataProtocol() {
		middleLength = pattern.paddingLength(pattern.middlePad)
		meta.prefixLen = byte(middleLength)
	}
	endLength := pattern.paddingLength(pattern.endPad)
	meta.suffixLen = byte(endLength)
	plain := meta.marshal(u.metadataScratch[:0], time.Now())
	capacity := len(plain) + authTagSize + nonceSize + middleLength + endLength
	if len(payload) != 0 {
		capacity += len(payload) + authTagSize
	}
	output := make([]byte, 0, capacity)
	var err error
	output, err = u.send.encrypt(output, plain, u.user.name, pattern)
	if err != nil {
		return err
	}
	output, err = appendRandom(output, middleLength)
	if err != nil {
		return err
	}
	if len(payload) != 0 {
		output, err = u.send.encrypt(output, payload, u.user.name, pattern)
		if err != nil {
			return err
		}
	}
	output, err = appendRandom(output, endLength)
	if err != nil {
		return err
	}
	if pattern.tcpFragment && meta.sessionProtocol() {
		return u.writeFragmented(output, pattern.tcpMaxSleep)
	}
	for len(output) != 0 {
		n, writeErr := u.conn.Write(output)
		if writeErr != nil {
			return writeErr
		}
		output = output[n:]
	}
	return nil
}

func (u *streamUnderlay) writeFragmented(output []byte, maxSleep int) error {
	total := len(output)
	minimum := int(math.Sqrt(float64(total))) + 1
	maximum := max(minimum, total/2)
	for len(output) != 0 {
		length := minimum + randomInt(maximum-minimum+1)
		if length > len(output) {
			length = len(output)
		}
		written, err := u.conn.Write(output[:length])
		if err != nil {
			return err
		}
		output = output[written:]
		if len(output) != 0 && maxSleep > 0 {
			time.Sleep(time.Duration(randomInt(maxSleep+1)) * time.Millisecond)
		}
	}
	return nil
}

func (u *streamUnderlay) close() {
	u.once.Do(func() {
		if u.cancel != nil {
			u.cancel()
		}
		close(u.done)
		_ = u.conn.Close()
		u.sessions.Range(func(_, value any) bool {
			value.(*session).closeRemote()
			return true
		})
	})
}
