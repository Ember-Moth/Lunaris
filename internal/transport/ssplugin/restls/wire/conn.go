// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Polaris contributors
package restls

import (
	"io"
	"net"

	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

const badRecordMACText = "tls: bad record MAC"

type Conn struct {
	net.Conn
	inbound net.Conn
}

func newConn(conn net.Conn, inbound net.Conn) *Conn {
	return &Conn{Conn: conn, inbound: inbound}
}

func (conn *Conn) Read(p []byte) (n int, err error) {
	n, err = conn.Conn.Read(p)
	return n, conn.normalizeReadError(err)
}

func (conn *Conn) ReadBuffer(buffer *buf.Buffer) error {
	n, err := conn.Conn.Read(buffer.FreeBytes())
	buffer.Truncate(buffer.Len() + n)
	return conn.normalizeReadError(err)
}

func (conn *Conn) WriteBuffer(buffer *buf.Buffer) error {
	defer buffer.Release()
	_, err := conn.Conn.Write(buffer.Bytes())
	return err
}

func (conn *Conn) normalizeReadError(err error) error {
	if err == nil || err.Error() != badRecordMACText || conn.inbound == nil {
		return err
	}
	if tracked, ok := conn.inbound.(*recordTrackingConn); ok && tracked.lastRecordIsCloseNotify() {
		return io.EOF
	}
	return err
}

var _ N.ExtendedConn = (*Conn)(nil)
