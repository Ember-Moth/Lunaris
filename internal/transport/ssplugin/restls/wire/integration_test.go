// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Polaris contributors
package restls

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	engine "github.com/metacubex/restls-client-go"
	M "github.com/sagernet/sing/common/metadata"
)

func TestClientCloseBecomesServerEOF(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(target.Close)
	server, err := NewServer(ServerConfig{
		Handshake: M.ParseSocksaddr(target.Listener.Addr().String()),
		Password:  "integration-password",
	})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	serverResult := make(chan error, 1)
	go func() {
		serverRaw, err := listener.Accept()
		if err != nil {
			serverResult <- err
			return
		}
		_ = serverRaw.SetDeadline(time.Now().Add(5 * time.Second))
		conn, err := server.NewConnection(context.Background(), serverRaw)
		if err != nil {
			serverResult <- err
			return
		}
		defer conn.Close()
		request := make([]byte, len("request"))
		if _, err = io.ReadFull(conn, request); err != nil {
			serverResult <- err
			return
		}
		if _, err = conn.Write([]byte("response")); err != nil {
			serverResult <- err
			return
		}
		_, err = conn.Read(make([]byte, 1))
		if !errors.Is(err, io.EOF) {
			serverResult <- err
			return
		}
		serverResult <- nil
	}()
	clientRaw, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientRaw.Close() })
	_ = clientRaw.SetDeadline(time.Now().Add(5 * time.Second))

	clientConfig, err := engine.NewRestlsConfig("example.com", "integration-password", "tls13", "", "chrome")
	if err != nil {
		t.Fatal(err)
	}
	clientConfig.InsecureSkipVerify = true
	clientConfig.MinVersion = engine.VersionTLS13
	clientConfig.MaxVersion = engine.VersionTLS13
	client := engine.UClient(clientRaw, clientConfig, engine.HelloChrome_Auto)
	if err = client.HandshakeContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err = client.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len("response"))
	if _, err = io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	if err = client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-serverResult:
		if err != nil {
			t.Fatalf("server close result: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not observe client close")
	}
}
