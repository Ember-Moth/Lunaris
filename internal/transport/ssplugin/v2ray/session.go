// SPDX-License-Identifier: MPL-2.0
// Derived and modified from XTLS/Xray-core common/mux at b17a88f9b46d.

package v2ray

import (
	"context"
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
	sessionQueueSize = 8
	sessionChunkSize = 16 * 1024
)

type muxSession struct {
	ctx        context.Context
	cancel     context.CancelFunc
	server     *muxServer
	id         uint16
	metadata   M.Metadata
	app        net.Conn
	bridge     net.Conn
	incoming   chan *queuedPayload
	enqueueMu  sync.Mutex
	queued     atomic.Int64
	queueFreed chan struct{}
	once       sync.Once
}

func newMuxSession(parent context.Context, server *muxServer, id uint16, metadata M.Metadata) *muxSession {
	ctx, cancel := context.WithCancel(parent)
	app, bridge := net.Pipe()
	return &muxSession{
		ctx: ctx, cancel: cancel, server: server, id: id, metadata: metadata,
		app: app, bridge: bridge, incoming: make(chan *queuedPayload, sessionQueueSize),
		queueFreed: make(chan struct{}, 1),
	}
}

func (session *muxSession) start() {
	session.server.wait.Add(3)
	go session.deliver()
	go session.upload()
	go session.serve()
}

func (session *muxSession) enqueue(payload *queuedPayload) error {
	if payload == nil {
		return nil
	}
	session.enqueueMu.Lock()
	defer session.enqueueMu.Unlock()
	if session.ctx.Err() != nil {
		return net.ErrClosed
	}
	if err := session.reserveQueued(payload.size); err != nil {
		return err
	}
	select {
	case session.incoming <- payload:
		return nil
	case <-session.ctx.Done():
		session.releaseQueuedBytes(payload.size)
		return net.ErrClosed
	}
}

func (session *muxSession) reserveQueued(size int) error {
	limit := int64(session.server.service.config.MaxSessionQueuedBytes)
	if int64(size) > limit {
		return errQueueLimit
	}
	for {
		current := session.queued.Load()
		if current+int64(size) <= limit && session.queued.CompareAndSwap(current, current+int64(size)) {
			return nil
		}
		select {
		case <-session.queueFreed:
		case <-session.ctx.Done():
			return net.ErrClosed
		}
	}
}

func (session *muxSession) releaseQueuedBytes(size int) {
	session.queued.Add(-int64(size))
	select {
	case session.queueFreed <- struct{}{}:
	default:
	}
}

func (session *muxSession) deliver() {
	defer session.server.wait.Done()
	defer session.releaseQueued()
	for {
		select {
		case payload := <-session.incoming:
			err := writePipe(session.bridge, payload.buffer.Bytes())
			session.releaseQueuedBytes(payload.size)
			payload.release()
			if err != nil {
				session.close(true)
				return
			}
		case <-session.ctx.Done():
			return
		}
	}
}

func (session *muxSession) upload() {
	defer session.server.wait.Done()
	buffer := buf.NewSize(sessionChunkSize + 8)
	defer buffer.Release()
	for {
		buffer.Resize(8, 0)
		_, err := buffer.ReadOnceFrom(session.bridge)
		if buffer.Len() > 0 {
			header := buffer.ExtendHeader(8)
			if writeErr := session.server.writeData(session.id, header, buffer.Bytes()); writeErr != nil {
				session.server.report(session.ctx, writeErr)
				_ = session.server.conn.Close()
				session.close(false)
				return
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) && session.ctx.Err() == nil {
				session.server.report(session.ctx, err)
			}
			session.close(true)
			return
		}
	}
}

func (session *muxSession) serve() {
	defer session.server.wait.Done()
	if err := session.app.SetReadDeadline(time.Now().Add(session.server.service.config.HandshakeTimeout)); err != nil {
		session.server.report(session.ctx, err)
		session.close(true)
		return
	}
	if err := session.server.service.downstream.NewConnection(session.ctx, session.app, session.metadata); err != nil {
		session.server.report(session.ctx, err)
	}
	session.close(true)
}

func (session *muxSession) close(notify bool) {
	session.once.Do(func() {
		session.server.remove(session.id, session)
		session.server.service.releaseStream()
		session.cancel()
		_ = session.bridge.Close()
		_ = session.app.Close()
		if notify {
			_ = session.server.writeEnd(session.id)
		}
	})
}

func (session *muxSession) releaseQueued() {
	session.enqueueMu.Lock()
	defer session.enqueueMu.Unlock()
	for {
		select {
		case payload := <-session.incoming:
			session.releaseQueuedBytes(payload.size)
			payload.release()
		default:
			return
		}
	}
}

func writePipe(conn net.Conn, payload []byte) error {
	for len(payload) > 0 {
		written, err := conn.Write(payload)
		if err != nil {
			return err
		}
		if written == 0 {
			return net.ErrClosed
		}
		payload = payload[written:]
	}
	return nil
}
