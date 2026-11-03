// SPDX-License-Identifier: GPL-3.0-only
package egress

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/pipe"
)

// A UDP association may contact both families. Keep at most one socket per
// family so adding an IPv6 destination never breaks an IPv4-bound association.
// Each reader holds at most one datagram; all readers join on Close.
type sourcePacketConn struct {
	source        netip.Addr
	mu            sync.Mutex
	sockets       map[bool]net.PacketConn
	initial       net.Addr
	writeDeadline time.Time
	deadline      pipe.Deadline
	results       chan packetResult
	done          chan struct{}
	closed        bool
	wg            sync.WaitGroup
	once          sync.Once
}
type packetResult struct {
	data     []byte
	from     net.Addr
	err      error
	consumed chan struct{}
}

func newSourcePacketConn(ctx context.Context, source netip.Addr, destination M.Socksaddr) (net.PacketConn, error) {
	c := &sourcePacketConn{source: source, sockets: make(map[bool]net.PacketConn), deadline: pipe.MakeDeadline(), results: make(chan packetResult), done: make(chan struct{})}
	first := source.Is4()
	if destination.Addr.IsValid() {
		first = destination.Addr.Unmap().Is4()
	}
	if _, err := c.socket(ctx, first); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}
func (c *sourcePacketConn) socket(ctx context.Context, ipv4 bool) (net.PacketConn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, net.ErrClosed
	}
	if socket := c.sockets[ipv4]; socket != nil {
		return socket, nil
	}
	network, address := "udp6", "[::]:0"
	if ipv4 {
		network, address = "udp4", "0.0.0.0:0"
	}
	bind := c.source.Is4() == ipv4
	if bind {
		address = net.JoinHostPort(c.source.String(), "0")
	}
	socket, err := (&net.ListenConfig{}).ListenPacket(ctx, network, address)
	if bind && unavailableSource(err) {
		address = "[::]:0"
		if ipv4 {
			address = "0.0.0.0:0"
		}
		socket, err = (&net.ListenConfig{}).ListenPacket(ctx, network, address)
	}
	if err != nil {
		return nil, err
	}
	if err = socket.SetWriteDeadline(c.writeDeadline); err != nil {
		socket.Close()
		return nil, err
	}
	c.sockets[ipv4] = socket
	if c.initial == nil {
		c.initial = socket.LocalAddr()
	}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		buffer := make([]byte, 65535)
		for {
			n, from, err := socket.ReadFrom(buffer)
			consumed := make(chan struct{})
			select {
			case c.results <- packetResult{buffer[:n], from, err, consumed}:
			case <-c.done:
				return
			}
			select {
			case <-consumed:
			case <-c.done:
				return
			}
			if err != nil {
				return
			}
		}
	}()
	return socket, nil
}
func (c *sourcePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-c.done:
		return 0, nil, net.ErrClosed
	default:
	}
	select {
	case result := <-c.results:
		defer close(result.consumed)
		n := copy(p, result.data)
		if n < len(result.data) {
			return n, result.from, io.ErrShortBuffer
		}
		return n, result.from, result.err
	case <-c.done:
		return 0, nil, net.ErrClosed
	case <-c.deadline.Wait():
		return 0, nil, os.ErrDeadlineExceeded
	}
}
func (c *sourcePacketConn) WriteTo(p []byte, address net.Addr) (int, error) {
	dst := M.SocksaddrFromNet(address).Unwrap()
	if !dst.Addr.IsValid() {
		return 0, &net.AddrError{Err: "UDP destination must be an IP", Addr: address.String()}
	}
	socket, err := c.socket(context.Background(), dst.Addr.Is4())
	if err != nil {
		return 0, err
	}
	return socket.WriteTo(p, dst.UDPAddr())
}
func (c *sourcePacketConn) LocalAddr() net.Addr               { c.mu.Lock(); defer c.mu.Unlock(); return c.initial }
func (c *sourcePacketConn) SetReadDeadline(t time.Time) error { c.deadline.Set(t); return nil }
func (c *sourcePacketConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.writeDeadline = t
	for _, socket := range c.sockets {
		if err := socket.SetWriteDeadline(t); err != nil {
			return err
		}
	}
	return nil
}
func (c *sourcePacketConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}
func (c *sourcePacketConn) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		close(c.done)
		for _, socket := range c.sockets {
			socket.Close()
		}
		c.mu.Unlock()
		c.wg.Wait()
	})
	return nil
}
