// SPDX-License-Identifier: GPL-3.0-or-later
// Adapted from Polaris; see THIRD_PARTY_NOTICES.md.
package shadowtls

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	protocol "github.com/sagernet/sing-shadowtls"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

var errShadowTLSDownstream = errors.New("shadowtls downstream result")

type testDownstream struct {
	metadata chan M.Metadata
}

func (downstream testDownstream) NewConnection(_ context.Context, conn net.Conn, metadata M.Metadata) error {
	downstream.metadata <- metadata
	payload := make([]byte, 4)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return err
	}
	if _, err := conn.Write([]byte("pong")); err != nil {
		return err
	}
	return errShadowTLSDownstream
}

func TestServiceAdaptsShadowTLSConnection(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(target.Close)
	metadataResult := make(chan M.Metadata, 1)
	service, err := NewService(Config{
		Version: 1, HandshakeAddress: target.Listener.Addr().String(),
	}, testDownstream{metadata: metadataResult})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	deadline := time.Now().Add(5 * time.Second)
	wantMetadata := M.Metadata{Source: M.ParseSocksaddr("127.0.0.1:1234")}
	serverResult := make(chan error, 1)
	go func() {
		serverRaw, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		defer func() { _ = serverRaw.Close() }()
		_ = serverRaw.SetDeadline(deadline)
		serverResult <- service.NewConnection(context.Background(), serverRaw, wantMetadata)
	}()
	clientRaw, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientRaw.Close() })
	_ = clientRaw.SetDeadline(deadline)
	client, err := protocol.NewClient(protocol.ClientConfig{
		Version: 1, Logger: logger.NOP(),
		TLSHandshake: protocol.DefaultTLSHandshakeFunc("", &tls.Config{
			ServerName: "example.com", InsecureSkipVerify: true, // Test-only target certificate.
			MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := client.DialContextConn(context.Background(), clientRaw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 4)
	if _, err = io.ReadFull(conn, payload); err != nil || string(payload) != "pong" {
		t.Fatalf("response = %q, %v", payload, err)
	}
	select {
	case got := <-metadataResult:
		if got.Source != wantMetadata.Source {
			t.Fatalf("metadata = %#v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("downstream did not receive metadata")
	}
	select {
	case err = <-serverResult:
		if !errors.Is(err, errShadowTLSDownstream) {
			t.Fatalf("server result = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not propagate downstream result")
	}
}
