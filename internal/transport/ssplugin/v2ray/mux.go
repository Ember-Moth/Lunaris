// SPDX-License-Identifier: MPL-2.0
// Derived and modified from XTLS/Xray-core common/mux at b17a88f9b46d.

package v2ray

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	statusNew       = byte(0x01)
	statusKeep      = byte(0x02)
	statusEnd       = byte(0x03)
	statusKeepAlive = byte(0x04)
	optionData      = byte(0x01)
	optionError     = byte(0x02)
	maxMetadata     = 512
	writeTimeout    = 5 * time.Second
)

var (
	errInvalidFrame = errors.New("shadowsocks: invalid v2ray-plugin mux frame")
	errSessionLimit = errors.New("shadowsocks: v2ray-plugin mux session limit reached")
	errQueueLimit   = errors.New("shadowsocks: v2ray-plugin mux receive queue limit reached")
)

type muxServer struct {
	conn       net.Conn
	service    *Service
	writeMu    sync.Mutex
	mu         sync.Mutex
	sessions   map[uint16]*muxSession
	wait       sync.WaitGroup
	queued     atomic.Int64
	queueFreed chan struct{}
}

func newMuxServer(conn net.Conn, service *Service) *muxServer {
	return &muxServer{
		conn: conn, service: service, sessions: make(map[uint16]*muxSession),
		queueFreed: make(chan struct{}, 1),
	}
}

func (server *muxServer) serve(ctx context.Context, metadata M.Metadata) error {
	done := make(chan struct{})
	defer func() {
		close(done)
		_ = server.conn.Close()
		server.closeSessions()
		server.wait.Wait()
	}()
	go func() {
		select {
		case <-ctx.Done():
			_ = server.conn.Close()
		case <-done:
		}
	}()
	for {
		err := server.readFrame(ctx, metadata)
		if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func (server *muxServer) readFrame(ctx context.Context, metadata M.Metadata) error {
	var lengthBytes [2]byte
	if _, err := io.ReadFull(server.conn, lengthBytes[:]); err != nil {
		return err
	}
	metadataLength := int(binary.BigEndian.Uint16(lengthBytes[:]))
	if metadataLength < 4 || metadataLength > maxMetadata {
		return errInvalidFrame
	}
	var storage [maxMetadata]byte
	frame := storage[:metadataLength]
	if _, err := io.ReadFull(server.conn, frame); err != nil {
		return err
	}
	id := binary.BigEndian.Uint16(frame[:2])
	status, option := frame[2], frame[3]
	payload, err := server.readPayload(ctx, option)
	if err != nil {
		return err
	}
	if payload != nil {
		defer func() {
			if payload != nil {
				payload.release()
			}
		}()
	}
	switch status {
	case statusNew:
		if len(frame) < 8 || frame[4] != 0x01 {
			return errInvalidFrame
		}
		session, err := server.newSession(ctx, id, metadata)
		if errors.Is(err, errSessionLimit) {
			return server.writeEnd(id)
		}
		if err != nil {
			return err
		}
		err = session.enqueue(payload)
		if err == nil {
			payload = nil
		}
		return err
	case statusKeep:
		session := server.session(id)
		if session == nil {
			_ = server.writeEnd(id)
			return nil
		}
		if option&optionError != 0 {
			session.close(false)
			return nil
		}
		err = session.enqueue(payload)
		if err == nil {
			payload = nil
		}
		return err
	case statusEnd:
		if session := server.session(id); session != nil {
			session.close(false)
		}
		return nil
	case statusKeepAlive:
		return nil
	default:
		return errInvalidFrame
	}
}

type queuedPayload struct {
	buffer *buf.Buffer
	server *muxServer
	size   int
}

func (payload *queuedPayload) release() {
	payload.buffer.Release()
	payload.server.releaseQueued(payload.size)
}

func (server *muxServer) readPayload(ctx context.Context, option byte) (*queuedPayload, error) {
	if option&optionData == 0 {
		return nil, nil
	}
	var lengthBytes [2]byte
	if _, err := io.ReadFull(server.conn, lengthBytes[:]); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(lengthBytes[:]))
	if length == 0 {
		return nil, nil
	}
	if err := server.reserveQueued(ctx, length); err != nil {
		return nil, err
	}
	payload := buf.NewSize(length)
	if _, err := payload.ReadFullFrom(server.conn, length); err != nil {
		payload.Release()
		server.releaseQueued(length)
		return nil, err
	}
	return &queuedPayload{buffer: payload, server: server, size: length}, nil
}

func (server *muxServer) reserveQueued(ctx context.Context, size int) error {
	if size > server.service.config.MaxQueuedBytes {
		return errQueueLimit
	}
	for {
		current := server.queued.Load()
		if current+int64(size) <= int64(server.service.config.MaxQueuedBytes) &&
			server.queued.CompareAndSwap(current, current+int64(size)) {
			return nil
		}
		select {
		case <-server.queueFreed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (server *muxServer) releaseQueued(size int) {
	server.queued.Add(-int64(size))
	select {
	case server.queueFreed <- struct{}{}:
	default:
	}
}

func (server *muxServer) newSession(ctx context.Context, id uint16, metadata M.Metadata) (*muxSession, error) {
	server.mu.Lock()
	defer server.mu.Unlock()
	if _, exists := server.sessions[id]; exists {
		return nil, errInvalidFrame
	}
	if len(server.sessions) >= server.service.config.MaxSessions || !server.service.acquireStream() {
		return nil, errSessionLimit
	}
	session := newMuxSession(ctx, server, id, metadata)
	server.sessions[id] = session
	session.start()
	return session, nil
}

func (server *muxServer) session(id uint16) *muxSession {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.sessions[id]
}

func (server *muxServer) remove(id uint16, expected *muxSession) {
	server.mu.Lock()
	if server.sessions[id] == expected {
		delete(server.sessions, id)
	}
	server.mu.Unlock()
}

func (server *muxServer) closeSessions() {
	server.mu.Lock()
	sessions := make([]*muxSession, 0, len(server.sessions))
	for _, session := range server.sessions {
		sessions = append(sessions, session)
	}
	server.mu.Unlock()
	for _, session := range sessions {
		session.close(false)
	}
}

func (server *muxServer) report(ctx context.Context, err error) {
	if server.service.onError != nil {
		server.service.onError(ctx, err)
	}
}
