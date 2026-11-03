// SPDX-License-Identifier: GPL-3.0-only
package outbound

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// client owns pending handshakes and every returned connection. A successful
// dial detaches its request deadline, while generation retirement closes it.
type client struct {
	ctx         context.Context
	cancel      context.CancelFunc
	raw         ProtocolClient
	caps        Capabilities
	limits      model.Limits
	mu          sync.Mutex
	closed      bool
	connections map[io.Closer]struct{}
	active      sync.WaitGroup
	once        sync.Once
	done        chan struct{}
	closeErr    error
}

func newClient(ctx context.Context, raw ProtocolClient, caps Capabilities, limits model.Limits) *client {
	ctx, cancel := context.WithCancel(ctx)
	return &client{ctx: ctx, cancel: cancel, raw: raw, caps: caps, limits: limits, connections: make(map[io.Closer]struct{}), done: make(chan struct{})}
}
func (c *client) begin(ctx context.Context) (context.Context, func(), error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.ctx.Err() != nil {
		return nil, nil, net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	c.active.Add(1)
	work, cancel := context.WithTimeout(ctx, c.limits.DialTimeout)
	stop := context.AfterFunc(c.ctx, cancel)
	return work, func() { stop(); cancel(); c.active.Done() }, nil
}
func (c *client) attach(ctx context.Context, connection io.Closer) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.ctx.Err() != nil || ctx.Err() != nil {
		connection.Close()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return net.ErrClosed
	}
	c.connections[connection] = struct{}{}
	return nil
}
func (c *client) forget(connection io.Closer) {
	c.mu.Lock()
	delete(c.connections, connection)
	c.mu.Unlock()
}
func (c *client) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	if network != "tcp" || !c.caps.TCP {
		return nil, ErrUnsupportedNetwork
	}
	if !dst.IsValid() || dst.Port == 0 {
		return nil, errors.New("invalid outbound destination")
	}
	work, finish, err := c.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	conn, err := c.raw.DialContext(work, network, dst)
	if err != nil {
		if work.Err() != nil {
			return nil, work.Err()
		}
		return nil, err
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}
	// Attach the underlying handle so closing a raced candidate cannot recurse
	// into the client's ownership mutex through its tracking wrapper.
	if err = c.attach(work, conn); err != nil {
		return nil, err
	}
	return &trackedConn{Conn: conn, owner: c}, nil
}
func (c *client) ListenPacket(ctx context.Context, dst M.Socksaddr) (net.PacketConn, error) {
	if !c.caps.UDP {
		return nil, ErrUnsupportedNetwork
	}
	if !dst.IsValid() || dst.Port == 0 {
		return nil, errors.New("invalid outbound destination")
	}
	work, finish, err := c.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	conn, err := c.raw.ListenPacket(work, dst)
	if err != nil {
		if work.Err() != nil {
			return nil, work.Err()
		}
		return nil, err
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}
	if err = c.attach(work, conn); err != nil {
		return nil, err
	}
	return &trackedPacket{NetPacketConn: bufio.NewPacketConn(conn), raw: conn, owner: c}, nil
}
func (c *client) Close(ctx context.Context) error {
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.cancel()
		owned := make([]io.Closer, 0, len(c.connections))
		for conn := range c.connections {
			owned = append(owned, conn)
		}
		c.connections = make(map[io.Closer]struct{})
		c.mu.Unlock()
		go func() {
			defer close(c.done)
			for _, conn := range owned {
				conn.Close()
			}
			c.closeErr = c.raw.Close()
			c.active.Wait()
		}()
	})
	select {
	case <-c.done:
		return c.closeErr
	default:
	}
	select {
	case <-c.done:
		return c.closeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

type trackedConn struct {
	net.Conn
	owner *client
	once  sync.Once
	err   error
}

func (c *trackedConn) Close() error {
	c.once.Do(func() { c.err = c.Conn.Close(); c.owner.forget(c.Conn) })
	return c.err
}
func (c *trackedConn) Upstream() any { return c.Conn }

type trackedPacket struct {
	N.NetPacketConn
	raw   net.PacketConn
	owner *client
	once  sync.Once
	err   error
}

func (c *trackedPacket) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if buffer.FreeLen() >= 65535 {
		return c.NetPacketConn.ReadPacket(buffer)
	}
	wire := buf.NewSize(65535)
	defer wire.Release()
	source, err := c.NetPacketConn.ReadPacket(wire)
	if err != nil {
		return M.Socksaddr{}, err
	}
	if wire.Len() > buffer.FreeLen() {
		return M.Socksaddr{}, io.ErrShortBuffer
	}
	_, err = buffer.Write(wire.Bytes())
	return source, err
}
func (c *trackedPacket) ReadFrom(p []byte) (int, net.Addr, error) {
	buffer := buf.NewSize(65535)
	defer buffer.Release()
	source, err := c.NetPacketConn.ReadPacket(buffer)
	if err != nil {
		return 0, nil, err
	}
	n := copy(p, buffer.Bytes())
	if n < buffer.Len() {
		return n, source, io.ErrShortBuffer
	}
	return n, source, nil
}
func (c *trackedPacket) WritePacket(buffer *buf.Buffer, dst M.Socksaddr) error {
	defer buffer.Release()
	_, err := c.WriteTo(buffer.Bytes(), dst)
	return err
}
func (c *trackedPacket) WriteTo(p []byte, dst net.Addr) (int, error) {
	if len(p) > 65535 {
		return 0, errors.New("outbound packet is too large")
	}
	_, err := c.NetPacketConn.WriteTo(p, dst)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *trackedPacket) Close() error {
	c.once.Do(func() { c.err = c.raw.Close(); c.owner.forget(c.raw) })
	return c.err
}

// handshake guards synchronous upstream handshake APIs and clears the temporary
// deadline before handing an established stream back to the relay.
func handshake(ctx context.Context, conn net.Conn, work func() error) error {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { conn.Close(); close(done) })
	err := work()
	if !stop() {
		<-done
		if err == nil {
			err = ctx.Err()
		}
	}
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		err = conn.SetDeadline(time.Time{})
	}
	if err != nil {
		conn.Close()
	}
	return err
}

type handshakeDialer struct {
	N.Dialer
	timeout time.Duration
}

func (d handshakeDialer) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, network, dst)
	if err == nil && network == "tcp" {
		if err = conn.SetDeadline(time.Now().Add(d.timeout)); err != nil {
			conn.Close()
			return nil, err
		}
	}
	return conn, err
}
