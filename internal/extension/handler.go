// SPDX-License-Identifier: GPL-3.0-only
// Package extension handles authenticated UoT and sing-mux destinations.
package extension

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/transport"
	mux "github.com/sagernet/sing-mux"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

type Handler struct {
	next       transport.RelayHandler
	limits     model.Limits
	uot        bool
	uotVersion uint8
	muxEnabled bool
	mux        *mux.Service
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
	closed     bool
	pending    int
	entries    map[*ticket]struct{}
	wg         sync.WaitGroup
	once       sync.Once
	done       chan struct{}
}
type ticket struct {
	owner                *Handler
	conn                 net.Conn
	pending, done        bool // protected by owner.mu
	timer                *time.Timer
	stopParent, stopRoot func() bool
	once, closeOnce      sync.Once
}
type streamKey struct{}
type sessionKey struct{}
type rejectedKey struct{}

type Options struct {
	UDPOverTCP        bool
	UDPOverTCPVersion uint8
	Multiplex         model.Multiplex
}

func New(spec Options, limits model.Limits, next transport.RelayHandler, log logger.ContextLogger) (*Handler, error) {
	if spec.UDPOverTCPVersion != 0 && spec.UDPOverTCPVersion != uot.Version && spec.UDPOverTCPVersion != uot.LegacyVersion {
		return nil, errors.New("unsupported UoT wire version")
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := &Handler{next: next, limits: limits, uot: spec.UDPOverTCP, uotVersion: spec.UDPOverTCPVersion, muxEnabled: spec.Multiplex.Enabled, ctx: ctx, cancel: cancel, entries: make(map[*ticket]struct{}), done: make(chan struct{})}
	if log == nil {
		log = logger.NOP()
	}
	if h.muxEnabled {
		service, err := mux.NewService(mux.ServiceOptions{HandlerEx: h, Logger: log, Padding: spec.Multiplex.Padding, NewStreamContext: func(ctx context.Context, c net.Conn) context.Context {
			parent, _ := ctx.Value(sessionKey{}).(*ticket)
			if parent == nil || !parent.ready() {
				c.Close()
				return context.WithValue(ctx, rejectedKey{}, true)
			}
			entry := h.acquire(ctx, c)
			if entry == nil {
				c.Close()
				return context.WithValue(ctx, rejectedKey{}, true)
			}
			return context.WithValue(ctx, streamKey{}, entry)
		}})
		if err != nil {
			cancel()
			return nil, err
		}
		h.mux = service
	}
	return h, nil
}
func (h *Handler) acquire(ctx context.Context, c net.Conn) *ticket {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || ctx.Err() != nil || h.pending >= h.limits.MaxPendingHandshakes || len(h.entries) >= 2*h.limits.MaxConnections+h.limits.MaxUDPSessions {
		return nil
	}
	t := &ticket{owner: h, conn: c, pending: true}
	h.pending++
	h.entries[t] = struct{}{}
	h.wg.Add(1)
	_ = c.SetReadDeadline(time.Now().Add(h.limits.HandshakeTimeout))
	t.timer = time.AfterFunc(h.limits.HandshakeTimeout, t.expire)
	t.stopParent = context.AfterFunc(ctx, t.expire)
	t.stopRoot = context.AfterFunc(h.ctx, t.expire)
	return t
}
func (t *ticket) expire() { t.closeOnce.Do(func() { t.conn.Close() }); t.finish() }
func (t *ticket) finish() {
	t.once.Do(func() {
		h := t.owner
		h.mu.Lock()
		t.done = true
		if t.pending {
			t.pending = false
			h.pending--
		}
		t.timer.Stop()
		t.stopParent()
		t.stopRoot()
		delete(h.entries, t)
		h.mu.Unlock()
		h.wg.Done()
	})
}
func (t *ticket) ready() bool {
	h := t.owner
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || t.done {
		return false
	}
	if !t.pending {
		return true
	}
	if !t.timer.Stop() {
		return false
	}
	t.pending = false
	h.pending--
	_ = t.conn.SetReadDeadline(time.Time{})
	return true
}
func reject(c io.Closer, close N.CloseHandlerFunc) {
	_ = N.CloseOnHandshakeFailure(c, close, errors.New("disabled, invalid or limited connection extension"))
}
func finish(ctx context.Context, close N.CloseHandlerFunc) N.CloseHandlerFunc {
	t, _ := ctx.Value(streamKey{}).(*ticket)
	return N.OnceClose(func(err error) {
		if t != nil {
			t.finish()
		}
		if close != nil {
			close(err)
		}
	})
}
func ready(ctx context.Context) bool {
	if rejected, _ := ctx.Value(rejectedKey{}).(bool); rejected {
		return false
	}
	if t, ok := ctx.Value(streamKey{}).(*ticket); ok {
		return t.ready()
	}
	return true
}
func (h *Handler) NewConnectionEx(ctx context.Context, c net.Conn, src, dst M.Socksaddr, onClose N.CloseHandlerFunc) {
	if rejected, _ := ctx.Value(rejectedKey{}).(bool); rejected {
		reject(c, onClose)
		return
	}
	if strings.EqualFold(dst.Fqdn, mux.Destination.Fqdn) {
		if !h.muxEnabled || dst.Port != mux.Destination.Port || ctx.Value(sessionKey{}) != nil {
			reject(c, finish(ctx, onClose))
			return
		}
		// Closing the carrier drives the mux session to completion before its
		// context is cancelled; this also serializes upstream h2mux cleanup.
		sessionCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
		defer cancel()
		t := h.acquire(sessionCtx, c)
		if t == nil {
			reject(c, onClose)
			return
		}
		defer t.finish()
		h.mux.NewConnectionEx(context.WithValue(sessionCtx, sessionKey{}, t), c, src, dst, N.OnceClose(func(err error) {
			if onClose != nil {
				onClose(err)
			}
		}))
		return
	}
	if strings.EqualFold(dst.Fqdn, uot.MagicAddress) || strings.EqualFold(dst.Fqdn, uot.LegacyMagicAddress) {
		version := uint8(uot.LegacyVersion)
		if strings.EqualFold(dst.Fqdn, uot.MagicAddress) {
			version = uot.Version
		}
		if !h.uot || (h.uotVersion != 0 && h.uotVersion != version) {
			reject(c, finish(ctx, onClose))
			return
		}
		t, _ := ctx.Value(streamKey{}).(*ticket)
		if t == nil {
			t = h.acquire(ctx, c)
			if t == nil {
				reject(c, onClose)
				return
			}
			ctx = context.WithValue(ctx, streamKey{}, t)
		}
		h.serveUOT(ctx, c, src, version == uot.Version, finish(ctx, onClose))
		return
	}
	if !ready(ctx) {
		reject(c, finish(ctx, onClose))
		return
	}
	h.next.NewConnectionEx(ctx, c, src, dst, finish(ctx, onClose))
}
func (h *Handler) NewPacketConnectionEx(ctx context.Context, c N.PacketConn, src, dst M.Socksaddr, onClose N.CloseHandlerFunc) {
	if !ready(ctx) {
		reject(c, finish(ctx, onClose))
		return
	}
	if ctx.Value(sessionKey{}) != nil {
		c = newDeadlinePacket(c)
	}
	h.next.NewPacketConnectionEx(ctx, c, src, dst, finish(ctx, onClose))
}
func (h *Handler) serveUOT(ctx context.Context, c net.Conn, src M.Socksaddr, v2 bool, onClose N.CloseHandlerFunc) {
	request := uot.Request{}
	if v2 {
		r, err := uot.ReadRequest(c)
		if err != nil {
			reject(c, onClose)
			return
		}
		request = *r
	}
	packet := &uotPacket{Conn: uot.NewConn(c, request)}
	// Read the first actual datagram before handing off an unconnected session.
	// This gives relay a real destination, while preserving even empty datagrams.
	first := buf.NewSize(65535)
	dst, err := packet.ReadPacket(first)
	if err != nil {
		first.Release()
		reject(c, onClose)
		return
	}
	cached := &firstPacket{PacketConn: packet, buffer: first, destination: dst}
	if !ready(ctx) {
		reject(cached, onClose)
		return
	}
	h.next.NewPacketConnectionEx(ctx, newDeadlinePacket(cached), src, dst, onClose)
}

// Use the upstream WriteTo codec with explicit ownership of sing buffers.
type uotPacket struct{ *uot.Conn }

func (c *uotPacket) WritePacket(b *buf.Buffer, dst M.Socksaddr) error {
	defer b.Release()
	_, err := c.Conn.WriteTo(b.Bytes(), dst)
	return err
}

type firstPacket struct {
	N.PacketConn
	mu          sync.Mutex
	buffer      *buf.Buffer
	destination M.Socksaddr
}

func (c *firstPacket) ReadPacket(out *buf.Buffer) (M.Socksaddr, error) {
	c.mu.Lock()
	b := c.buffer
	c.buffer = nil
	c.mu.Unlock()
	if b == nil {
		return c.PacketConn.ReadPacket(out)
	}
	defer b.Release()
	if out.FreeLen() < b.Len() {
		return M.Socksaddr{}, io.ErrShortBuffer
	}
	_, err := out.Write(b.Bytes())
	return c.destination, err
}
func (c *firstPacket) Close() error {
	c.mu.Lock()
	b := c.buffer
	c.buffer = nil
	c.mu.Unlock()
	if b != nil {
		b.Release()
	}
	return c.PacketConn.Close()
}
func (h *Handler) initiateClose() {
	h.once.Do(func() {
		h.mu.Lock()
		h.closed = true
		entries := make([]*ticket, 0, len(h.entries))
		for t := range h.entries {
			entries = append(entries, t)
		}
		h.mu.Unlock()
		h.cancel()
		go func() {
			for _, t := range entries {
				t.expire()
			}
			h.wg.Wait()
			close(h.done)
		}()
	})
}
func (h *Handler) Close(ctx context.Context) error {
	h.initiateClose()
	select {
	case <-h.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type Instance struct {
	transport.Instance
	Handler *Handler
}

func (i *Instance) Start(ctx context.Context) error {
	context.AfterFunc(ctx, i.Handler.initiateClose)
	return i.Instance.Start(ctx)
}
func (i *Instance) Stop(ctx context.Context) error {
	i.Handler.initiateClose()
	return errors.Join(i.Instance.Stop(ctx), i.Handler.Close(ctx))
}
func (i *Instance) Addr() net.Addr {
	if a, ok := i.Instance.(interface{ Addr() net.Addr }); ok {
		return a.Addr()
	}
	return nil
}

// HTTP/2 logical streams do not implement socket deadlines. UDP associations
// close on idle timeout, so enforce that deadline with an owned close timer.
type deadlinePacket struct {
	N.PacketConn
	mu     sync.Mutex
	timer  *time.Timer
	epoch  uint64
	closed bool
}

func newDeadlinePacket(c N.PacketConn) *deadlinePacket { return &deadlinePacket{PacketConn: c} }
func (c *deadlinePacket) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.epoch++
	epoch := c.epoch
	if c.timer != nil {
		c.timer.Stop()
	}
	if t.IsZero() {
		return nil
	}
	c.timer = time.AfterFunc(time.Until(t), func() {
		c.mu.Lock()
		if c.closed || c.epoch != epoch {
			c.mu.Unlock()
			return
		}
		c.closed = true
		c.mu.Unlock()
		c.PacketConn.Close()
	})
	return nil
}
func (c *deadlinePacket) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	if c.timer != nil {
		c.timer.Stop()
	}
	c.mu.Unlock()
	return c.PacketConn.Close()
}
func (c *deadlinePacket) FrontHeadroom() int {
	if v, ok := c.PacketConn.(interface{ FrontHeadroom() int }); ok {
		return v.FrontHeadroom()
	}
	return 0
}
func (c *deadlinePacket) RearHeadroom() int {
	if v, ok := c.PacketConn.(interface{ RearHeadroom() int }); ok {
		return v.RearHeadroom()
	}
	return 0
}
