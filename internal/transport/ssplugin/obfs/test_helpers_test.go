// SPDX-License-Identifier: GPL-3.0-or-later
// Adapted from Polaris; see THIRD_PARTY_NOTICES.md.
package obfs

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

type chunkReader struct {
	reader  io.Reader
	maximum int
}

func (reader *chunkReader) Read(payload []byte) (int, error) {
	return reader.reader.Read(payload[:min(len(payload), reader.maximum)])
}

type obfsTestConn struct {
	reader io.Reader
	writer io.Writer
	access sync.Mutex
}

func (conn *obfsTestConn) Read(payload []byte) (int, error) {
	conn.access.Lock()
	defer conn.access.Unlock()
	if conn.reader == nil {
		return 0, io.EOF
	}
	return conn.reader.Read(payload)
}

func (conn *obfsTestConn) Write(payload []byte) (int, error) {
	conn.access.Lock()
	defer conn.access.Unlock()
	if conn.writer == nil {
		return len(payload), nil
	}
	return conn.writer.Write(payload)
}

func (*obfsTestConn) Close() error                     { return nil }
func (*obfsTestConn) LocalAddr() net.Addr              { return obfsTestAddr("local") }
func (*obfsTestConn) RemoteAddr() net.Addr             { return obfsTestAddr("remote") }
func (*obfsTestConn) SetDeadline(time.Time) error      { return nil }
func (*obfsTestConn) SetReadDeadline(time.Time) error  { return nil }
func (*obfsTestConn) SetWriteDeadline(time.Time) error { return nil }

type obfsTestAddr string

func (address obfsTestAddr) Network() string { return "test" }
func (address obfsTestAddr) String() string  { return string(address) }

var errObfsTestTemporary = errors.New("temporary test interruption")

type interruptReader struct {
	data        []byte
	offset      int
	interruptAt int
	interrupted bool
}

func (reader *interruptReader) Read(payload []byte) (int, error) {
	if !reader.interrupted && reader.offset == reader.interruptAt {
		reader.interrupted = true
		return 0, errObfsTestTemporary
	}
	if reader.offset == len(reader.data) {
		return 0, io.EOF
	}
	limit := len(payload)
	if !reader.interrupted && reader.offset < reader.interruptAt {
		limit = min(limit, reader.interruptAt-reader.offset)
	}
	limit = min(limit, len(reader.data)-reader.offset)
	copy(payload, reader.data[reader.offset:reader.offset+limit])
	reader.offset += limit
	return limit, nil
}

type shortWriter struct{}

func (shortWriter) Write(payload []byte) (int, error) { return len(payload) / 2, nil }
