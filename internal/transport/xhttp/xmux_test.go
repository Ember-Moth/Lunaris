// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package xhttp

import (
	"sync/atomic"
	"testing"
)

type fakeXMUXConn struct {
	closed atomic.Bool
}

func (conn *fakeXMUXConn) IsClosed() bool { return conn.closed.Load() }
func (conn *fakeXMUXConn) Close() error   { conn.closed.Store(true); return nil }

func TestXMUXMaxConnections(t *testing.T) {
	manager := newXMUXManager(XMUXConfig{MaxConnections: Range{From: 4, To: 4}}, func() xmuxConn { return new(fakeXMUXConn) })
	defer func() { _ = manager.Close() }()
	clients := make(map[*xmuxClient]struct{})
	for range 8 {
		clients[manager.get()] = struct{}{}
	}
	if len(clients) != 4 {
		t.Fatalf("distinct clients = %d, want 4", len(clients))
	}
}

func TestXMUXReuseAndConcurrency(t *testing.T) {
	t.Run("reuse", func(t *testing.T) {
		manager := newXMUXManager(XMUXConfig{CMaxReuseTimes: Range{From: 2, To: 2}}, func() xmuxConn { return new(fakeXMUXConn) })
		defer func() { _ = manager.Close() }()
		clients := make(map[*xmuxClient]struct{})
		for range 64 {
			clients[manager.get()] = struct{}{}
		}
		if len(clients) != 32 {
			t.Fatalf("distinct clients = %d, want 32", len(clients))
		}
	})
	t.Run("concurrency", func(t *testing.T) {
		manager := newXMUXManager(XMUXConfig{MaxConcurrency: Range{From: 2, To: 2}}, func() xmuxConn { return new(fakeXMUXConn) })
		defer func() { _ = manager.Close() }()
		clients := make(map[*xmuxClient]struct{})
		for range 64 {
			client := manager.get()
			client.addRunning()
			clients[client] = struct{}{}
		}
		if len(clients) != 32 {
			t.Fatalf("distinct clients = %d, want 32", len(clients))
		}
	})
}

func TestXMUXCloseDefersActiveConnection(t *testing.T) {
	manager := newXMUXManager(XMUXConfig{}, func() xmuxConn { return new(fakeXMUXConn) })
	client := manager.get()
	client.addRunning()
	_ = manager.Close()
	if manager.get() != nil {
		t.Fatal("closed manager created a replacement connection")
	}
	if client.conn.IsClosed() {
		t.Fatal("active connection closed before its stream finished")
	}
	client.doneRunning()
	if !client.conn.IsClosed() {
		t.Fatal("unused connection was not closed")
	}
}

func TestXMUXLeaseTransfersUploadReference(t *testing.T) {
	initial := &xmuxClient{conn: new(fakeXMUXConn)}
	replacement := &xmuxClient{conn: new(fakeXMUXConn)}
	lease := newXMUXLease(initial, initial)
	if initial.running.Load() != 1 {
		t.Fatalf("initial running = %d, want 1", initial.running.Load())
	}
	if !lease.replaceUpload(replacement) {
		t.Fatal("upload lease transfer failed")
	}
	if initial.running.Load() != 1 || replacement.running.Load() != 1 {
		t.Fatalf("running after transfer = initial %d, replacement %d", initial.running.Load(), replacement.running.Load())
	}
	lease.Close()
	if initial.running.Load() != 0 || replacement.running.Load() != 0 {
		t.Fatalf("running after close = initial %d, replacement %d", initial.running.Load(), replacement.running.Load())
	}
}

func TestXMUXRequestKeepsRetiredTransportAlive(t *testing.T) {
	initial := &xmuxClient{conn: new(fakeXMUXConn)}
	download := &xmuxClient{conn: new(fakeXMUXConn)}
	replacement := &xmuxClient{conn: new(fakeXMUXConn)}
	lease := newXMUXLease(initial, download)
	initial.addRequest()
	initial.notUsed.Store(true)
	if !lease.replaceUpload(replacement) {
		t.Fatal("upload lease transfer failed")
	}
	if initial.conn.IsClosed() {
		t.Fatal("retired transport closed with an upload response still pending")
	}
	initial.doneRequest()
	if !initial.conn.IsClosed() {
		t.Fatal("retired transport remained open after its last request finished")
	}
	lease.Close()
}
