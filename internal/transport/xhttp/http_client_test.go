// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package xhttp

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestH2KeepaliveRequiresExplicitPeriod(t *testing.T) {
	if duration := keepaliveDuration(0); duration != 0 {
		t.Fatalf("default keepalive = %s", duration)
	}
	if duration := keepaliveDuration(-1); duration != 0 {
		t.Fatalf("disabled keepalive = %s", duration)
	}
	if duration := keepaliveDuration(20); duration != 20*time.Second {
		t.Fatalf("explicit keepalive = %s", duration)
	}
}

func TestHTTP2UsesStandardTransport(t *testing.T) {
	config := Config{XMUX: XMUXConfig{HKeepAlivePeriod: 20}}
	client := newDefaultDialerClient(config, true, true, nil)
	transport, ok := client.transport.(*http.Transport)
	if !ok {
		t.Fatalf("HTTP/2 transport = %T, want *http.Transport", client.transport)
	}
	if transport.Protocols == nil || !transport.Protocols.HTTP2() ||
		transport.Protocols.HTTP1() || transport.Protocols.UnencryptedHTTP2() {
		t.Fatalf("HTTP/2 protocols = %v, want only encrypted HTTP/2", transport.Protocols)
	}
	if transport.HTTP2 == nil || transport.HTTP2.SendPingTimeout != 20*time.Second {
		t.Fatalf("HTTP/2 config = %+v, want 20s ping interval", transport.HTTP2)
	}
}

func TestOpenStreamReportsDownloadHTTPStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	client := newDefaultDialerClient(Config{}, false, false, func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	})
	defer func() { _ = client.Close() }()
	if _, _, _, err := client.openStream(context.Background(), server.URL, "session", nil, false); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("openStream error = %v, want HTTP 403", err)
	}
}

func TestH1PacketUploadReadsOwnResponseBeforeReuse(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.Copy(io.Discard, request.Body)
		if requests.Add(1) == 2 {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	var dials atomic.Int32
	config := Config{UplinkHTTPMethod: http.MethodPost, UplinkDataPlacement: PlacementBody, ScMaxBufferedPosts: 2, ScMaxEachPostBytes: Range{From: 4, To: 4}}
	client := newDefaultDialerClient(config, false, false, func(ctx context.Context) (net.Conn, error) {
		dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	})
	defer func() { _ = client.Close() }()
	if err := client.postPacket(context.Background(), server.URL, "session", "0", []byte("one"), func() {}); err != nil {
		t.Fatal(err)
	}
	if err := client.postPacket(context.Background(), server.URL, "session", "1", []byte("two"), func() {}); err == nil {
		t.Fatal("second packet upload did not report its HTTP 500 response")
	}
	if dials.Load() != 1 {
		t.Fatalf("TCP dials = %d, want one reused connection", dials.Load())
	}
}
