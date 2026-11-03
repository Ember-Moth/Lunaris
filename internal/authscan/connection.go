// SPDX-License-Identifier: GPL-3.0-only
package authscan

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"

	N "github.com/sagernet/sing/common/network"
)

// PrefixConn replays only the bytes consumed by credential selection. It must
// keep half-close semantics and must never expose an unconsumed upstream reader.
type PrefixConn struct {
	net.Conn
	Prefix *bytes.Reader
}

func ReplayPrefix(conn net.Conn, prefix []byte) *PrefixConn {
	return &PrefixConn{Conn: conn, Prefix: bytes.NewReader(prefix)}
}
func (c *PrefixConn) Read(p []byte) (int, error) {
	if c.Prefix.Len() > 0 {
		return c.Prefix.Read(p)
	}
	return c.Conn.Read(p)
}
func (c *PrefixConn) CloseRead() error  { return N.CloseRead(c.Conn) }
func (c *PrefixConn) CloseWrite() error { return N.CloseWrite(c.Conn) }

// Rejected excludes incomplete handshakes and shutdown from source penalties.
func Rejected(err error) bool {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
		return false
	}
	var timeout net.Error
	return !errors.As(err, &timeout) || !timeout.Timeout()
}
