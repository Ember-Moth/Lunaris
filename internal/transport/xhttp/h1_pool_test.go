// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package xhttp

import (
	"bufio"
	"net"
	"testing"
)

func TestH1ConnPoolCloseClosesIdleConnections(t *testing.T) {
	local, remote := net.Pipe()
	pool := newH1ConnPool(1)
	pool.Put(&h1Conn{Conn: local, reader: bufio.NewReader(local)})
	if err := pool.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := remote.Read(make([]byte, 1)); err == nil {
		t.Fatal("remote connection remained open")
	}
	_ = remote.Close()
}
