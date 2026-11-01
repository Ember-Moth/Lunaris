// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package native

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type packetConn struct {
	conn    net.Conn
	readMu  sync.Mutex
	writeMu sync.Mutex
}

func newPacketConn(conn net.Conn) N.PacketConn { return &packetConn{conn: conn} }

func (c *packetConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	var prefix [3]byte
	if _, err := io.ReadFull(c.conn, prefix[:]); err != nil {
		return M.Socksaddr{}, err
	}
	length := int(binary.BigEndian.Uint16(prefix[1:]))
	if prefix[0] != 0 || !buffer.IsEmpty() || length > buffer.FreeLen() {
		return M.Socksaddr{}, io.ErrShortBuffer
	}
	if _, err := buffer.ReadFullFrom(c.conn, length); err != nil {
		return M.Socksaddr{}, err
	}
	var suffix [1]byte
	if _, err := io.ReadFull(c.conn, suffix[:]); err != nil {
		return M.Socksaddr{}, err
	}
	if suffix[0] != 0xff || buffer.Len() < 4 || buffer.Byte(0) != 0 || buffer.Byte(1) != 0 || buffer.Byte(2) != 0 {
		return M.Socksaddr{}, fmt.Errorf("sing-mieru: invalid SOCKS5 UDP packet")
	}
	buffer.Advance(3)
	return M.SocksaddrSerializer.ReadAddrPort(buffer)
}

func (c *packetConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	header := buf.NewSize(3 + M.SocksaddrSerializer.AddrPortLen(destination))
	defer header.Release()
	_ = header.WriteZeroN(3)
	if err := M.SocksaddrSerializer.WriteAddrPort(header, destination); err != nil {
		return err
	}
	length := header.Len() + buffer.Len()
	if length > 65535 {
		return io.ErrShortBuffer
	}
	var prefix [3]byte
	binary.BigEndian.PutUint16(prefix[1:], uint16(length))
	suffix := []byte{0xff}
	buffers := net.Buffers{prefix[:], header.Bytes(), buffer.Bytes(), suffix}
	_, err := buffers.WriteTo(c.conn)
	return err
}

func (c *packetConn) Close() error                       { return c.conn.Close() }
func (c *packetConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *packetConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *packetConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *packetConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
func (c *packetConn) Upstream() any                      { return c.conn }

var _ N.PacketConn = (*packetConn)(nil)
