// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Polaris contributors
package restls

import (
	"errors"
	"io"
	"net"
	"testing"

	"github.com/sagernet/sing/common/buf"
)

func TestConnNormalizesBadMACFollowedByPeerClose(t *testing.T) {
	inbound, peer := net.Pipe()
	tracked := newRecordTrackingConn(inbound)
	tracked.last = tlsRecordMeta{typ: tlsApplicationData, version: tlsLegacyRecordVersion, length: 19}
	engine := &readErrorConn{Conn: tracked, err: errors.New(badRecordMACText)}
	conn := newConn(engine, tracked)
	t.Cleanup(func() { _ = inbound.Close(); _ = peer.Close() })

	_, err := conn.Read(make([]byte, 1))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("Read() error = %v, want EOF", err)
	}
}

func TestConnKeepsBadMACWhilePeerIsOpen(t *testing.T) {
	inbound, peer := net.Pipe()
	t.Cleanup(func() { _ = inbound.Close(); _ = peer.Close() })
	want := errors.New(badRecordMACText)
	conn := newConn(&readErrorConn{Conn: inbound, err: want}, inbound)

	_, err := conn.Read(make([]byte, 1))
	if !errors.Is(err, want) {
		t.Fatalf("Read() error = %v, want %v", err, want)
	}
}

func TestConnUsesSingExtendedBuffers(t *testing.T) {
	inbound, peer := net.Pipe()
	conn := newConn(inbound, inbound)
	buffer := buf.New()
	t.Cleanup(func() { _ = conn.Close(); _ = peer.Close(); buffer.Release() })
	go func() { _, _ = peer.Write([]byte("payload")) }()

	if err := conn.ReadBuffer(buffer); err != nil {
		t.Fatal(err)
	}
	if string(buffer.Bytes()) != "payload" {
		t.Fatalf("ReadBuffer() = %q", buffer.Bytes())
	}
}

type readErrorConn struct {
	net.Conn
	err error
}

func (conn *readErrorConn) Read([]byte) (int, error) { return 0, conn.err }
