// SPDX-License-Identifier: GPL-3.0-only
package shadowsocks

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/ingress"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/pipe"
)

type packet struct {
	buffer      *buf.Buffer
	destination M.Socksaddr
}

const maxQueuedPayloadBytes = 16 << 20

func (s *Server) reservePacketBytes(n int) bool {
	s.queueMu.Lock()
	defer s.queueMu.Unlock()
	if s.queuedBytes+n > maxQueuedPayloadBytes {
		return false
	}
	s.queuedBytes += n
	return true
}

func (s *Server) releasePacketBytes(n int) {
	s.queueMu.Lock()
	s.queuedBytes -= n
	s.queueMu.Unlock()
}

// packetSession implements sing's PacketConn; queue ownership is explicit and
// Close releases all queued buffers before it returns. A full queue drops input.
type packetSessionKey struct {
	source, local netip.AddrPort
	user          int
}

type packetSession struct {
	user     int
	method   *shadowaead.Method
	local    netip.AddrPort
	server   *Server
	writer   N.PacketWriter
	source   netip.AddrPort
	mu       sync.Mutex
	closed   bool
	queue    chan packet
	done     chan struct{}
	deadline pipe.Deadline
}

func newPacketSession(server *Server, source netip.AddrPort, locals ...netip.AddrPort) *packetSession {
	var local netip.AddrPort
	if len(locals) > 0 {
		local = locals[0]
	}
	return &packetSession{server: server, method: server.method, source: source, local: local, queue: make(chan packet, server.limits.UDPQueueSize), done: make(chan struct{}), deadline: pipe.MakeDeadline()}
}

func (c *packetSession) offer(buffer *buf.Buffer, destination M.Socksaddr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		buffer.Release()
		return
	}
	if !c.server.reservePacketBytes(buffer.Len()) {
		buffer.Release()
		return
	}
	select {
	case c.queue <- packet{buffer, destination}:
	default:
		c.server.releasePacketBytes(buffer.Len())
		buffer.Release()
	}
}

func (c *packetSession) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	select {
	case packet := <-c.queue:
		c.server.releasePacketBytes(packet.buffer.Len())
		defer packet.buffer.Release()
		if buffer.FreeLen() < packet.buffer.Len() {
			return M.Socksaddr{}, io.ErrShortBuffer
		}
		_, err := buffer.Write(packet.buffer.Bytes())
		return packet.destination, err
	case <-c.done:
		return M.Socksaddr{}, net.ErrClosed
	case <-c.deadline.Wait():
		return M.Socksaddr{}, os.ErrDeadlineExceeded
	}
}

func (c *packetSession) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	select {
	case <-c.done:
		buffer.Release()
		return net.ErrClosed
	default:
	}
	if c.writer != nil {
		return c.writer.WritePacket(buffer, destination)
	}
	encoder := c.method.DialPacketConn(&datagramConn{write: func(packet []byte) (int, error) {
		// Register before exposing the ciphertext to the network. Classic AEAD
		// packet framing is symmetric, so a response must not authenticate as input.
		if len(packet) < c.server.saltSize || !c.server.replay.accept(c.server.replayKey(c.user, packet[:c.server.saltSize])) {
			return 0, errors.New("Shadowsocks response salt rejected")
		}
		c.server.writeMu.Lock()
		defer c.server.writeMu.Unlock()
		if err := c.server.udp.SetWriteDeadline(time.Now().Add(c.server.limits.DialTimeout)); err != nil {
			return 0, err
		}
		return ingress.WritePacket(c.server.udp, packet, net.UDPAddrFromAddrPort(c.source), c.LocalAddr())
	}})
	// Classic AEAD UDP is symmetric: the upstream codec supplies salt, HKDF,
	// encryption and address framing in both directions. No wire code is forked.
	return encoder.WritePacket(buffer, destination)
}

func (c *packetSession) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	close(c.done)
drain:
	for {
		select {
		case packet := <-c.queue:
			c.server.releasePacketBytes(packet.buffer.Len())
			packet.buffer.Release()
		default:
			break drain
		}
	}
	c.mu.Unlock()
	c.server.mu.Lock()
	if c.server.sessions[packetSessionKey{source: c.source, local: c.local, user: c.user}] == c {
		delete(c.server.sessions, packetSessionKey{source: c.source, local: c.local, user: c.user})
	}
	c.server.mu.Unlock()
	return nil
}

func (c *packetSession) LocalAddr() net.Addr {
	if c.local.IsValid() {
		return net.UDPAddrFromAddrPort(c.local)
	}
	return &net.UDPAddr{}
}
func (c *packetSession) SetDeadline(t time.Time) error     { return c.SetReadDeadline(t) }
func (c *packetSession) SetReadDeadline(t time.Time) error { c.deadline.Set(t); return nil }
func (*packetSession) SetWriteDeadline(time.Time) error    { return nil }
func (c *packetSession) FrontHeadroom() int {
	if c.writer != nil {
		return N.CalculateFrontHeadroom(c.writer)
	}
	return 512
}
func (c *packetSession) RearHeadroom() int {
	if c.writer != nil {
		return N.CalculateRearHeadroom(c.writer)
	}
	return 16
}
func (*packetSession) ReaderMTU() int { return 65535 }

// datagramConn adapts exactly one encrypted datagram to the upstream codec.
// It never owns or closes the shared listener socket.
type datagramConn struct {
	packet []byte
	write  func([]byte) (int, error)
}

func (c *datagramConn) Read(p []byte) (int, error) {
	if c.packet == nil {
		return 0, io.EOF
	}
	n := copy(p, c.packet)
	length := len(c.packet)
	c.packet = nil
	if n < length {
		return n, io.ErrShortBuffer
	}
	return n, nil
}
func (c *datagramConn) Write(p []byte) (int, error) {
	if c.write == nil {
		return 0, net.ErrClosed
	}
	return c.write(p)
}
func (*datagramConn) Close() error                     { return nil }
func (*datagramConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*datagramConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (*datagramConn) SetDeadline(time.Time) error      { return nil }
func (*datagramConn) SetReadDeadline(time.Time) error  { return nil }
func (*datagramConn) SetWriteDeadline(time.Time) error { return nil }

var _ N.PacketConn = (*packetSession)(nil)
