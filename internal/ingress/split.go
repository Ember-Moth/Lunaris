// SPDX-License-Identifier: GPL-3.0-only
package ingress

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing/common/pipe"
)

// ServeByLocal gives datagram carriers that key sessions only by remote address
// (KCP) separate virtual sockets for each local destination. Limits are shared
// by the carrier, and queued payload across these sockets is capped at 16 MiB.
func ServeByLocal(ctx context.Context, conn net.PacketConn, serve func(context.Context, net.PacketConn) error) error {
	if _, ok := conn.(LocalPacketConn); !ok {
		return serve(ctx, conn)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	owner := &packetSplit{conn: conn}
	children := map[netip.AddrPort]*localSocket{}
	var wg sync.WaitGroup
	results := make(chan error, 64)
	// Interrupt the shared read on lifecycle cancellation. The transport owns
	// final socket closure; no detached read goroutine survives this call.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })
	defer func() {
		stop()
		cancel()
		for _, c := range children {
			c.Close()
		}
		wg.Wait()
	}()
	buffer := make([]byte, 65535)
	for {
		n, remote, local, err := ReadPacket(conn, buffer)
		if err != nil {
			return err
		}
		select {
		case err := <-results:
			return err
		default:
		}
		endpoint, err := netip.ParseAddrPort(local.String())
		if err != nil {
			return err
		}
		child := children[endpoint]
		if child == nil {
			if len(children) >= 64 {
				continue
			}
			child = &localSocket{owner: owner, local: local, queue: make(chan localDatagram, 32), done: make(chan struct{}), deadline: pipe.MakeDeadline()}
			children[endpoint] = child
			wg.Add(1)
			go func(c *localSocket) {
				defer wg.Done()
				err := serve(ctx, c)
				if err == nil {
					err = net.ErrClosed
				}
				results <- err
				cancel()
			}(child)
		}
		child.offer(buffer[:n], remote)
	}
}

type packetSplit struct {
	conn  net.PacketConn
	mu    sync.Mutex
	bytes int
	write sync.Mutex
}
type localDatagram struct {
	data   []byte
	remote net.Addr
}
type localSocket struct {
	owner         *packetSplit
	local         net.Addr
	queue         chan localDatagram
	done          chan struct{}
	deadline      pipe.Deadline
	mu            sync.Mutex
	closed        bool
	writeDeadline time.Time
}

func (s *packetSplit) reserve(n int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bytes+n > 16<<20 {
		return false
	}
	s.bytes += n
	return true
}
func (s *packetSplit) release(n int) { s.mu.Lock(); s.bytes -= n; s.mu.Unlock() }
func (c *localSocket) offer(p []byte, remote net.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || !c.owner.reserve(len(p)) {
		return
	}
	item := localDatagram{append([]byte(nil), p...), remote}
	select {
	case c.queue <- item:
	default:
		c.owner.release(len(p))
	}
}
func (c *localSocket) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case packet := <-c.queue:
		c.owner.release(len(packet.data))
		n := copy(p, packet.data)
		if n < len(packet.data) {
			return n, packet.remote, io.ErrShortBuffer
		}
		return n, packet.remote, nil
	case <-c.done:
		return 0, nil, net.ErrClosed
	case <-c.deadline.Wait():
		return 0, nil, os.ErrDeadlineExceeded
	}
}
func (c *localSocket) WriteTo(p []byte, remote net.Addr) (int, error) {
	c.mu.Lock()
	closed, deadline := c.closed, c.writeDeadline
	c.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	c.owner.write.Lock()
	defer c.owner.write.Unlock()
	if err := c.owner.conn.SetWriteDeadline(deadline); err != nil {
		return 0, err
	}
	return WritePacket(c.owner.conn, p, remote, c.local)
}
func (c *localSocket) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	close(c.done)
	for {
		select {
		case packet := <-c.queue:
			c.owner.release(len(packet.data))
		default:
			return nil
		}
	}
}
func (c *localSocket) LocalAddr() net.Addr               { return c.local }
func (c *localSocket) SetReadDeadline(t time.Time) error { c.deadline.Set(t); return nil }
func (c *localSocket) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}
func (c *localSocket) SetDeadline(t time.Time) error {
	return errors.Join(c.SetReadDeadline(t), c.SetWriteDeadline(t))
}
