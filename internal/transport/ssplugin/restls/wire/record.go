// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Polaris contributors
package restls

import (
	"net"
	"sync"
)

const (
	tlsRecordHeaderLen     = 5
	tlsApplicationData     = 23
	tlsLegacyRecordVersion = 0x0303
)

type tlsRecordMeta struct {
	typ     byte
	version uint16
	length  int
}

type recordTrackingConn struct {
	net.Conn
	mu        sync.Mutex
	header    [tlsRecordHeaderLen]byte
	headerLen int
	remaining int
	current   tlsRecordMeta
	last      tlsRecordMeta
}

func newRecordTrackingConn(conn net.Conn) *recordTrackingConn {
	return &recordTrackingConn{Conn: conn}
}

func (conn *recordTrackingConn) Read(p []byte) (int, error) {
	n, err := conn.Conn.Read(p)
	if n > 0 {
		conn.track(p[:n])
	}
	return n, err
}

func (conn *recordTrackingConn) track(data []byte) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	for len(data) > 0 {
		if conn.headerLen < tlsRecordHeaderLen {
			n := copy(conn.header[conn.headerLen:], data)
			conn.headerLen += n
			data = data[n:]
			if conn.headerLen < tlsRecordHeaderLen {
				return
			}
			conn.current = tlsRecordMeta{
				typ:     conn.header[0],
				version: uint16(conn.header[1])<<8 | uint16(conn.header[2]),
				length:  int(conn.header[3])<<8 | int(conn.header[4]),
			}
			conn.remaining = conn.current.length
		}
		n := min(conn.remaining, len(data))
		conn.remaining -= n
		data = data[n:]
		if conn.remaining == 0 {
			conn.last = conn.current
			conn.resetRecord()
		}
	}
}

func (conn *recordTrackingConn) resetRecord() {
	conn.headerLen = 0
	conn.remaining = 0
	conn.current = tlsRecordMeta{}
}

func (conn *recordTrackingConn) lastRecordIsCloseNotify() bool {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.last.typ != tlsApplicationData || conn.last.version != tlsLegacyRecordVersion {
		return false
	}
	switch conn.last.length {
	case 18, 19, 26, 32, 48, 64, 80:
		return true
	default:
		return false
	}
}
