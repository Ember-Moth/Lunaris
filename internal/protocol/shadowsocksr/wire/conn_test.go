// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package shadowsocksr

import (
	"bytes"
	"errors"
	"github.com/sagernet/sing/common/buf"
	"net"
	"testing"
	"time"
)

func TestServerConnCloseUnblocksConcurrentReadAndWrite(t *testing.T) {
	server, err := NewServer(ServerConfig{
		Method: "none", Password: "server-key", Protocol: "origin", Obfs: "plain", Port: 8388,
	}, map[[4]byte]string{{1}: "user-key"})
	if err != nil {
		t.Fatal(err)
	}
	raw, peer := net.Pipe()
	defer peer.Close()
	conn, err := server.WrapConn(raw)
	if err != nil {
		t.Fatal(err)
	}
	readDone := make(chan error, 1)
	writeDone := make(chan error, 1)
	go func() {
		_, readErr := conn.Read(make([]byte, 32))
		readDone <- readErr
	}()
	go func() {
		_, writeErr := conn.Write([]byte("blocked write"))
		writeDone <- writeErr
	}()
	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
	for operation, done := range map[string]<-chan error{"read": readDone, "write": writeDone} {
		select {
		case operationErr := <-done:
			if operationErr == nil {
				t.Fatalf("%s unexpectedly succeeded after close", operation)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s remained blocked after close", operation)
		}
	}
	if _, err = conn.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("read after close = %v, want net.ErrClosed", err)
	}
	if _, err = conn.Write([]byte{1}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write after close = %v, want net.ErrClosed", err)
	}
}

func TestReadFrameRetainsInputAfterPoolReuse(t *testing.T) {
	server, err := NewServer(ServerConfig{Method: "none", Password: "test", Protocol: "origin", Obfs: "plain", Port: 8388}, map[[4]byte]string{{1}: "test"})
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0xa5}, 1000)
	for range 32 {
		raw, peer := net.Pipe()
		conn, err := server.WrapConn(raw)
		if err != nil {
			t.Fatal(err)
		}
		written := make(chan error, 1)
		go func() { _, err := peer.Write(payload); written <- err }()
		decoded, _, err := conn.readFrame(nil)
		if err != nil {
			t.Fatal(err)
		}
		if err = <-written; err != nil {
			t.Fatal(err)
		}
		scratch := buf.NewSize(serverStreamMTU)
		_ = scratch.WriteZeroN(serverStreamMTU)
		if !bytes.Equal(decoded, payload) {
			t.Fatal("readFrame returned bytes from a released receive buffer")
		}
		scratch.Release()
		conn.Close()
		peer.Close()
	}
}
