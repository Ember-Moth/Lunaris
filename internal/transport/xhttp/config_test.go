// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package xhttp

import (
	"crypto/tls"
	"testing"
	"time"
)

func TestParseDefaultsAndOverrides(t *testing.T) {
	config, err := Parse("front.example", "/outer", ModePacketUp, `{
		"host":"ignored.example","path":"/ignored","mode":"stream-one",
		"xPaddingBytes":"120-100","scMaxEachPostBytes":{"from":512,"to":256}
	}`)
	if err != nil {
		t.Fatal(err)
	}
	if config.Host != "front.example" || config.Path != "/outer" || config.Mode != ModePacketUp {
		t.Fatalf("top-level fields did not override extra: %+v", config)
	}
	if config.XPaddingBytes != (Range{From: 100, To: 120}) {
		t.Fatalf("padding range = %+v", config.XPaddingBytes)
	}
	if config.ScMaxEachPostBytes != (Range{From: 256, To: 512}) {
		t.Fatalf("post range = %+v", config.ScMaxEachPostBytes)
	}
	if config.XMUX.MaxConnections != (Range{From: 3, To: 3}) ||
		config.XMUX.HMaxRequestTimes.From != 600 || config.XMUX.HMaxReusableSecs.From != 1800 {
		t.Fatalf("unexpected XMUX defaults: %+v", config.XMUX)
	}
}

func TestRequestURLHostPriority(t *testing.T) {
	config := Config{Path: "/x", SessionIDPlacement: PlacementPath}
	if host := config.requestURL("127.0.0.1:8443", nil).Host; host != "127.0.0.1" {
		t.Fatalf("plaintext host = %q", host)
	}
	tlsConfig := &tls.Config{ServerName: "tls.example"}
	if host := config.requestURL("127.0.0.1:8443", tlsConfig).Host; host != "tls.example" {
		t.Fatalf("TLS host = %q", host)
	}
	config.Host = "front.example"
	if host := config.requestURL("127.0.0.1:8443", tlsConfig).Host; host != "front.example" {
		t.Fatalf("configured host = %q", host)
	}
	config.Host = ""
	if host := config.requestURL("[::1]:8443", nil).Host; host != "[::1]" {
		t.Fatalf("IPv6 host = %q", host)
	}
}

func TestParseDownloadSettings(t *testing.T) {
	extra := `{
		"downloadSettings": {
			"address":"127.0.0.1","port":8443,"network":"xhttp","security":"tls",
			"tlsSettings":{"serverName":"download.example","allowInsecure":true,"alpn":["h2"]},
			"xhttpSettings":{"path":"/download","mode":"packet-up"}
		}
	}`
	config, err := Parse("", "/upload", ModePacketUp, extra)
	if err != nil {
		t.Fatal(err)
	}
	if config.Download == nil || config.Download.Address != "127.0.0.1:8443" {
		t.Fatalf("unexpected download destination: %+v", config.Download)
	}
	if config.Download.TLSConfig == nil || config.Download.TLSConfig.ServerName != "download.example" {
		t.Fatalf("unexpected download TLS: %+v", config.Download.TLSConfig)
	}
	if config.Download.Transport.Path != "/download" {
		t.Fatalf("unexpected download transport: %+v", config.Download.Transport)
	}
}

func TestNestedExtraUsesOuterIdentity(t *testing.T) {
	config, err := buildConfig(rawConfig{
		Host: "outer.example", Path: "/outer", Mode: ModePacketUp,
		Extra: []byte(`{"host":"ignored.example","path":"/ignored","mode":"stream-one","noSSEHeader":true}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if config.Host != "outer.example" || config.Path != "/outer" || config.Mode != ModePacketUp || !config.NoSSEHeader {
		t.Fatalf("unexpected nested extra result: %+v", config)
	}
}

func TestParseRejectsInvalidCombinations(t *testing.T) {
	tests := []struct {
		name  string
		mode  string
		extra string
	}{
		{"unknown mode", "invalid", ""},
		{"conflicting xmux", ModePacketUp, `{"xmux":{"maxConnections":2,"maxConcurrency":2}}`},
		{"stream header payload", ModeStreamUp, `{"uplinkDataPlacement":"header"}`},
		{"negative post size", ModePacketUp, `{"scMaxEachPostBytes":-1}`},
		{"negative queue size", ModePacketUp, `{"scMaxBufferedPosts":-1}`},
		{"negative active sessions", ModePacketUp, `{"scMaxActiveSessions":-1}`},
		{"excessive active sessions", ModePacketUp, `{"scMaxActiveSessions":1048577}`},
		{"negative concurrent requests", ModePacketUp, `{"scMaxConcurrentRequests":-1}`},
		{"stream-one download", ModeStreamOne, `{"downloadSettings":{"address":"127.0.0.1","port":80,"network":"xhttp","xhttpSettings":{}}}`},
		{"unknown server backend", ModePacketUp, `{"serverBackend":"unknown"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Parse("", "/x", test.mode, test.extra); err == nil {
				t.Fatal("expected parse error")
			}
		})
	}
}

// The fasthttp backend was removed; a node pinned to it must fail loudly rather
// than fall through to net/http.
func TestParseRejectsRemovedServerBackend(t *testing.T) {
	if _, err := Parse("", "/x", ModePacketUp, `{"serverBackend":"fasthttp"}`); err == nil {
		t.Fatal("fasthttp server backend was accepted")
	}
	if _, err := Parse("", "/x", ModePacketUp, `{"serverBackend":"net/http"}`); err != nil {
		t.Fatalf("net/http server backend rejected: %v", err)
	}
}

func TestHTTP2MemoryBounds(t *testing.T) {
	config, err := Parse("", "/x", ModePacketUp, "")
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(t.Context(), config, nil, echoHandler{})
	if server.http.HTTP2.MaxReadFrameSize != httpRelayMTU ||
		server.http.HTTP2.MaxReceiveBufferPerConnection != 1<<20 ||
		server.http.HTTP2.MaxReceiveBufferPerStream != 1<<20 {
		t.Fatalf("unexpected HTTP/2 memory bounds: %+v", server.http.HTTP2)
	}
	conn := new(splitConn)
	if conn.ReaderMTU() != httpRelayMTU || conn.WriterMTU() != httpRelayMTU {
		t.Fatalf("unexpected relay MTU: read=%d write=%d", conn.ReaderMTU(), conn.WriterMTU())
	}
}

func TestHTTP3ReceiveWindowsGrowFromSmallInitialCredit(t *testing.T) {
	config, err := Parse("", "/x", ModePacketUp, "")
	if err != nil {
		t.Fatal(err)
	}
	quicConfig := h3QUICConfig(config, true)
	if quicConfig.InitialStreamReceiveWindow != h3InitialStreamReceiveWindow ||
		quicConfig.MaxStreamReceiveWindow != h3MaxStreamReceiveWindow ||
		quicConfig.InitialConnectionReceiveWindow != h3InitialConnectionReceiveWindow ||
		quicConfig.MaxConnectionReceiveWindow != h3MaxConnectionReceiveWindow {
		t.Fatalf("unexpected HTTP/3 receive windows: %+v", quicConfig)
	}
	if quicConfig.InitialStreamReceiveWindow >= quicConfig.MaxStreamReceiveWindow ||
		quicConfig.InitialConnectionReceiveWindow >= quicConfig.MaxConnectionReceiveWindow {
		t.Fatal("HTTP/3 receive windows cannot auto-tune")
	}
	if config.ScMaxBufferedBytes != 4<<20 || config.ScMaxTotalBufferedBytes != 256<<20 {
		t.Fatalf("unexpected upload byte budgets: per-session=%d total=%d", config.ScMaxBufferedBytes, config.ScMaxTotalBufferedBytes)
	}
	if config.ScMaxActiveSessions != 16_384 {
		t.Fatalf("active session limit = %d, want 16384", config.ScMaxActiveSessions)
	}
	if config.ScMaxConcurrentRequests != 16_384 {
		t.Fatalf("concurrent request limit = %d, want 16384", config.ScMaxConcurrentRequests)
	}
	if config.XMUX.MaxConnections != (Range{From: 3, To: 3}) {
		t.Fatalf("default maxConnections = %+v, want 3", config.XMUX.MaxConnections)
	}
}

func TestHTTP3ReceiveWindowsCanBeTunedFromExtra(t *testing.T) {
	config, err := Parse("", "/x", ModePacketUp, `{
		"h3InitialStreamReceiveWindow": 131072,
		"h3MaxStreamReceiveWindow": 1048576,
		"h3InitialConnectionReceiveWindow": 262144,
		"h3MaxConnectionReceiveWindow": 4194304
	}`)
	if err != nil {
		t.Fatal(err)
	}
	quicConfig := h3QUICConfig(config, true)
	if quicConfig.InitialStreamReceiveWindow != 128<<10 || quicConfig.MaxStreamReceiveWindow != 1<<20 ||
		quicConfig.InitialConnectionReceiveWindow != 256<<10 || quicConfig.MaxConnectionReceiveWindow != 4<<20 {
		t.Fatalf("unexpected configured HTTP/3 receive windows: %+v", quicConfig)
	}
}

func TestHTTP3ReceiveWindowsRejectInvalidBounds(t *testing.T) {
	_, err := Parse("", "/x", ModePacketUp, `{
		"h3InitialStreamReceiveWindow": 2097152,
		"h3MaxStreamReceiveWindow": 1048576
	}`)
	if err == nil {
		t.Fatal("expected invalid HTTP/3 receive window error")
	}
}

func TestRandomStringPowerOfTwoAlphabet(t *testing.T) {
	result := make(chan string, 1)
	go func() { result <- randomString(32, "0123456789abcdef") }()
	select {
	case value := <-result:
		if len(value) != 32 {
			t.Fatal("incorrect identifier length")
		}
	case <-time.After(time.Second):
		t.Fatal("power-of-two alphabet stalled random generation")
	}
}
