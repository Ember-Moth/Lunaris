// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package xhttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type echoHandler struct{}

func (echoHandler) NewConnectionEx(_ context.Context, conn net.Conn, _, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		_, err := io.Copy(conn, conn)
		_ = conn.Close()
		if onClose != nil {
			onClose(err)
		}
	}()
}

func TestTransportModesHTTP1(t *testing.T) {
	for _, mode := range []string{ModePacketUp, ModeStreamUp, ModeStreamOne, ModeAuto} {
		t.Run(mode, func(t *testing.T) {
			config := testTransportConfig(t, mode)
			testTransportRoundTrip(t, config, nil, nil)
		})
	}
}

func TestTransportPlacements(t *testing.T) {
	tests := []struct {
		name  string
		extra string
	}{
		{"query-header-cookie", `{
			"sessionIDPlacement":"query","seqPlacement":"header","uplinkDataPlacement":"header",
			"uplinkChunkSize":80,"xPaddingObfsMode":true,"xPaddingPlacement":"cookie","xPaddingMethod":"tokenish"
		}`},
		{"header-cookie-query", `{
			"sessionIDPlacement":"header","seqPlacement":"cookie","uplinkDataPlacement":"cookie",
			"uplinkChunkSize":80,"xPaddingObfsMode":true,"xPaddingPlacement":"query"
		}`},
		{"cookie-query-header", `{
			"sessionIDPlacement":"cookie","seqPlacement":"query","uplinkDataPlacement":"body",
			"xPaddingObfsMode":true,"xPaddingPlacement":"header"
		}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config, err := Parse("", "/placements", ModePacketUp, test.extra)
			if err != nil {
				t.Fatal(err)
			}
			config.ScMaxEachPostBytes = Range{From: 257, To: 257}
			config.ScMinPostsIntervalMs = Range{From: 1, To: 1}
			config.XMUX = XMUXConfig{MaxConnections: Range{From: 1, To: 1}, HMaxRequestTimes: Range{From: 1000, To: 1000}}
			testTransportRoundTrip(t, config, nil, nil)
		})
	}
}

func TestTransportTLS(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	for _, protocol := range []string{"h2", "http/1.1", "h3"} {
		for _, mode := range []string{ModePacketUp, ModeStreamUp, ModeStreamOne} {
			t.Run(protocol+"/"+mode, func(t *testing.T) {
				serverConfig := serverTLS.Clone()
				serverConfig.NextProtos = []string{protocol}
				clientConfig := clientTLS.Clone()
				clientConfig.NextProtos = []string{protocol}
				testTransportRoundTrip(t, testTransportConfig(t, mode), serverConfig, clientConfig)
			})
		}
	}
}

func TestTransportXMUXRequestRollover(t *testing.T) {
	for _, mode := range []string{ModePacketUp, ModeStreamUp} {
		t.Run(mode, func(t *testing.T) {
			config := testTransportConfig(t, mode)
			config.XMUX = XMUXConfig{
				MaxConnections:   Range{From: 1, To: 1},
				HMaxRequestTimes: Range{From: 1, To: 1},
			}
			testTransportRoundTrip(t, config, nil, nil)
		})
	}
}

func TestClientCloseCancelsActiveConnection(t *testing.T) {
	config := testTransportConfig(t, ModePacketUp)
	listener, server, client := startTestTransport(t, config, nil, nil)
	defer func() { _ = listener.Close() }()
	defer func() { _ = server.Close() }()
	conn, err := client.DialContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Close(); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, readErr := conn.Read(make([]byte, 1))
		result <- readErr
	}()
	select {
	case err = <-result:
		if err == nil {
			t.Fatal("read succeeded after client close")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("active connection was not canceled")
	}
}

func testTransportConfig(t *testing.T, mode string) Config {
	t.Helper()
	config, err := Parse("", "/xhttp", mode, `{
		"xPaddingBytes":100,"scMaxEachPostBytes":257,"scMinPostsIntervalMs":1,
		"scStreamUpServerSecs":-1,"xmux":{"maxConnections":1,"hMaxRequestTimes":1000}
	}`)
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func testTransportRoundTrip(t *testing.T, config Config, serverTLS, clientTLS *tls.Config) {
	t.Helper()
	listener, server, client := startTestTransport(t, config, serverTLS, clientTLS)
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
		_ = listener.Close()
	})
	assertTransportRoundTrip(t, client)
}

func assertTransportRoundTrip(t *testing.T, client *Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	payload := bytes.Repeat([]byte("xhttp-round-trip-"), 512)
	if _, err = conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	output := make([]byte, len(payload))
	result := make(chan error, 1)
	go func() {
		_, readErr := io.ReadFull(conn, output)
		result <- readErr
	}()
	select {
	case err = <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("round trip timed out")
	}
	if !bytes.Equal(output, payload) {
		t.Fatal("round-trip payload mismatch")
	}
}

func startTestTransport(t *testing.T, config Config, serverTLS, clientTLS *tls.Config) (net.Listener, *Server, *Client) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(context.Background(), config, serverTLS, echoHandler{})
	if server.PacketBased() {
		packet, listenErr := (&net.ListenConfig{}).ListenPacket(context.Background(), "udp", listener.Addr().String())
		if listenErr != nil {
			_ = listener.Close()
			t.Fatal(listenErr)
		}
		go func() { _ = server.ServePacket(packet) }()
	} else {
		go func() { _ = server.Serve(listener) }()
	}
	client := NewClient(ClientOptions{
		Context: context.Background(), Config: config, Server: listener.Addr().String(), TLSConfig: clientTLS,
		Dial: testDialAddress,
	})
	return listener, server, client
}

func testDialAddress(ctx context.Context, address string, tlsConfig *tls.Config) (net.Conn, error) {
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil || tlsConfig == nil {
		return raw, err
	}
	secured := tls.Client(raw, tlsConfig)
	if err = secured.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return secured, nil
}
