// SPDX-License-Identifier: GPL-3.0-only
package relay

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/egress"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var ErrClosed = errors.New("relay closed")
var ErrLimit = errors.New("relay connection limit reached")

// Handler owns both pending dials and active flows of a single listener.
type Handler struct {
	ctx       context.Context
	cancel    context.CancelFunc
	dialer    N.Dialer
	limits    model.Limits
	mu        sync.Mutex
	closed    bool
	flows     map[*flow]struct{}
	tcp, udp  int
	wg        sync.WaitGroup
	closeOnce sync.Once
	done      chan struct{}
}

type flow struct {
	handler    *Handler
	ctx        context.Context
	cancel     context.CancelFunc
	stopParent func() bool
	udp        bool
	onClose    N.CloseHandlerFunc
	mu         sync.Mutex
	closed     bool
	resources  []io.Closer
}

func New(ctx context.Context, dialer N.Dialer, limits model.Limits) *Handler {
	ctx, cancel := context.WithCancel(ctx)
	return &Handler{ctx: ctx, cancel: cancel, dialer: dialer, limits: limits, flows: make(map[*flow]struct{}), done: make(chan struct{})}
}

func (h *Handler) acquire(ctx context.Context, client io.Closer, udp bool, onClose N.CloseHandlerFunc) (*flow, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.ctx.Err() != nil || ctx.Err() != nil {
		return nil, ErrClosed
	}
	if (udp && h.udp >= h.limits.MaxUDPSessions) || (!udp && h.tcp >= h.limits.MaxConnections) {
		return nil, ErrLimit
	}
	ctx, cancel := context.WithCancel(ctx)
	f := &flow{handler: h, ctx: ctx, cancel: cancel, udp: udp, onClose: onClose, resources: []io.Closer{client}}
	f.stopParent = context.AfterFunc(h.ctx, cancel)
	h.flows[f] = struct{}{}
	if udp {
		h.udp++
	} else {
		h.tcp++
	}
	h.wg.Add(1)
	return f, nil
}

func (f *flow) attach(resource io.Closer) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.ctx.Err() != nil {
		resource.Close()
		return false
	}
	f.resources = append(f.resources, resource)
	return true
}

func (f *flow) closeResources() {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	f.closed = true
	resources := f.resources
	f.resources = nil
	f.mu.Unlock()
	f.cancel()
	for _, resource := range resources {
		resource.Close()
	}
}

func (f *flow) finish(err error) {
	f.closeResources()
	f.stopParent()
	h := f.handler
	h.mu.Lock()
	delete(h.flows, f)
	if f.udp {
		h.udp--
	} else {
		h.tcp--
	}
	h.mu.Unlock()
	defer h.wg.Done()
	if f.onClose != nil {
		f.onClose(err)
	}
}

func reject(client io.Closer, onClose N.CloseHandlerFunc, err error) {
	_ = N.CloseOnHandshakeFailure(client, onClose, err)
}

func validDestination(destination M.Socksaddr) bool {
	return destination.IsValid() && destination.Port != 0 && destination.AddrString() != ""
}

func (h *Handler) NewConnectionEx(ctx context.Context, client net.Conn, _ M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	if !validDestination(destination) {
		reject(client, onClose, errors.New("invalid TCP destination"))
		return
	}
	f, err := h.acquire(ctx, client, false, onClose)
	if err != nil {
		reject(client, onClose, err)
		return
	}
	go func() {
		var result error
		defer func() { f.finish(result) }()
		dialCtx, cancel := context.WithTimeout(f.ctx, h.limits.DialTimeout)
		upstream, err := h.dialer.DialContext(dialCtx, "tcp", destination)
		cancel()
		if err != nil {
			_ = N.ReportHandshakeFailure(client, err)
			result = err
			return
		}
		if !f.attach(upstream) {
			result = ErrClosed
			return
		}
		if err := N.ReportConnHandshakeSuccess(client, upstream); err != nil {
			result = err
			return
		}
		result = bufio.CopyConn(f.ctx, client, upstream)
	}()
}

func (h *Handler) NewPacketConnectionEx(ctx context.Context, client N.PacketConn, _ M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	if !validDestination(destination) {
		reject(client, onClose, errors.New("invalid UDP destination"))
		return
	}
	f, err := h.acquire(ctx, client, true, onClose)
	if err != nil {
		reject(client, onClose, err)
		return
	}
	go func() {
		var result error
		defer func() { f.finish(result) }()
		dialCtx, cancel := context.WithTimeout(f.ctx, h.limits.DialTimeout)
		socket, err := h.dialer.ListenPacket(dialCtx, destination)
		cancel()
		if err != nil {
			_ = N.ReportHandshakeFailure(client, err)
			result = err
			return
		}
		if !f.attach(socket) {
			result = ErrClosed
			return
		}
		if err := N.ReportPacketConnHandshakeSuccess(client, socket); err != nil {
			result = err
			return
		}
		var upstream N.PacketConn
		if framed, ok := socket.(N.PacketConn); ok {
			upstream = framed
		} else {
			upstream = egress.NewPacketConn(f.ctx, socket, h.limits.DialTimeout, h.limits.MaxUDPDestinations)
		}
		result = bufio.CopyPacketConn(f.ctx, &idlePacketConn{PacketConn: client, timeout: h.limits.UDPIdleTimeout}, &idlePacketConn{PacketConn: upstream, timeout: h.limits.UDPIdleTimeout})
	}()
}

func (h *Handler) Close(ctx context.Context) error {
	h.closeOnce.Do(func() {
		h.mu.Lock()
		h.closed = true
		flows := make([]*flow, 0, len(h.flows))
		for f := range h.flows {
			flows = append(flows, f)
		}
		h.mu.Unlock()
		h.cancel()
		for _, f := range flows {
			f.closeResources()
		}
		go func() { h.wg.Wait(); close(h.done) }()
	})
	select {
	case <-h.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *Handler) Active() (tcp, udp int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.tcp, h.udp
}

// Idle time advances on successful traffic in either direction. Forward buffer
// requirements rather than hiding the protocol writer's headroom requirements.
type idlePacketConn struct {
	N.PacketConn
	timeout time.Duration
}

func (c *idlePacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if err := c.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
		return M.Socksaddr{}, err
	}
	return c.PacketConn.ReadPacket(buffer)
}

func (c *idlePacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	err := c.PacketConn.WritePacket(buffer, destination)
	if err == nil {
		_ = c.SetReadDeadline(time.Now().Add(c.timeout))
	}
	return err
}

func (c *idlePacketConn) FrontHeadroom() int { return N.CalculateFrontHeadroom(c.PacketConn) }
func (c *idlePacketConn) RearHeadroom() int  { return N.CalculateRearHeadroom(c.PacketConn) }
func (*idlePacketConn) ReaderMTU() int       { return 65535 }
