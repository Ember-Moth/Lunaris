// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package xhttp

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

func TestSplitConnReadDeadlineInterruptsBlockedRead(t *testing.T) {
	local, remote := net.Pipe()
	defer func() { _ = remote.Close() }()
	conn := &splitConn{reader: local, writer: local}
	if err := conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, err := conn.Read(make([]byte, 1))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read error = %v, want deadline exceeded", err)
	}
}

func TestSplitConnReadDeadlineCanBeCleared(t *testing.T) {
	local, remote := net.Pipe()
	defer func() { _ = local.Close() }()
	defer func() { _ = remote.Close() }()
	conn := &splitConn{reader: local, writer: local}
	if err := conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(30 * time.Millisecond)
		_, _ = remote.Write([]byte{'x'})
	}()
	buffer := make([]byte, 1)
	if _, err := conn.Read(buffer); err != nil {
		t.Fatal(err)
	}
	if buffer[0] != 'x' {
		t.Fatalf("payload = %q", buffer)
	}
}
