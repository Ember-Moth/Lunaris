// SPDX-License-Identifier: GPL-3.0-only
package shadowsocksr

import (
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/pipe"
)

type packetItem struct {
	buffer      *buf.Buffer
	destination M.Socksaddr
}
type packetConn struct {
	server      *server
	key         packetKey
	mu          sync.Mutex
	closed      bool
	incoming    chan packetItem
	done        chan struct{}
	deadline    pipe.Deadline
	readOptions N.ReadWaitOptions
}

func newPacketConn(s *server, key packetKey) *packetConn {
	return &packetConn{server: s, key: key, incoming: make(chan packetItem, s.limits.UDPQueueSize), done: make(chan struct{}), deadline: pipe.MakeDeadline()}
}
func (c *packetConn) deliver(b *buf.Buffer, dst M.Socksaddr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || !c.server.reserve(b.Len()) {
		b.Release()
		return
	}
	select {
	case c.incoming <- packetItem{b, dst}:
	default:
		c.server.release(b.Len())
		b.Release()
	}
}
func (c *packetConn) next() (*buf.Buffer, M.Socksaddr, error) {
	select {
	case item := <-c.incoming:
		c.server.release(item.buffer.Len())
		return item.buffer, item.destination, nil
	case <-c.done:
		return nil, M.Socksaddr{}, net.ErrClosed
	case <-c.deadline.Wait():
		return nil, M.Socksaddr{}, os.ErrDeadlineExceeded
	}
}
func (c *packetConn) ReadPacket(out *buf.Buffer) (M.Socksaddr, error) {
	b, dst, err := c.next()
	if err != nil {
		return dst, err
	}
	defer b.Release()
	if out.FreeLen() < b.Len() {
		return dst, io.ErrShortBuffer
	}
	_, err = out.Write(b.Bytes())
	return dst, err
}
func (c *packetConn) InitializeReadWaiter(options N.ReadWaitOptions) bool {
	c.readOptions = options
	return false
}
func (c *packetConn) WaitReadPacket() (*buf.Buffer, M.Socksaddr, error) {
	b, dst, err := c.next()
	if err != nil {
		return nil, dst, err
	}
	return c.readOptions.Copy(b), dst, nil
}
func (c *packetConn) WritePacket(b *buf.Buffer, dst M.Socksaddr) error {
	defer b.Release()
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	wire := buf.NewSize(M.SocksaddrSerializer.AddrPortLen(dst) + b.Len() + 1024)
	if err := M.SocksaddrSerializer.WriteAddrPort(wire, dst); err != nil {
		wire.Release()
		return err
	}
	_, _ = wire.Write(b.Bytes())
	encoded, err := c.server.codec.Encode(wire, c.key.user)
	if err != nil {
		wire.Release()
		return err
	}
	if encoded != wire {
		wire.Release()
	}
	return c.server.write(encoded, c.key.source, c.key.local)
}
func (c *packetConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	close(c.done)
	for {
		select {
		case item := <-c.incoming:
			c.server.release(item.buffer.Len())
			item.buffer.Release()
		default:
			c.mu.Unlock()
			c.server.mu.Lock()
			if c.server.sessions[c.key] == c {
				delete(c.server.sessions, c.key)
			}
			c.server.mu.Unlock()
			return nil
		}
	}
}
func (c *packetConn) LocalAddr() net.Addr               { return net.UDPAddrFromAddrPort(c.key.local) }
func (c *packetConn) SetDeadline(t time.Time) error     { return c.SetReadDeadline(t) }
func (c *packetConn) SetReadDeadline(t time.Time) error { c.deadline.Set(t); return nil }
func (*packetConn) SetWriteDeadline(time.Time) error    { return nil }
func (*packetConn) ReaderMTU() int                      { return 65535 }
