// SPDX-License-Identifier: GPL-3.0-or-later
// Adapted from Polaris; see THIRD_PARTY_NOTICES.md.
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

var errRestlsDownstream = errors.New("restls downstream result")

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
	return errRestlsDownstream
}

func TestServiceAdaptsRestlsConnection(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(target.Close)
	metadataResult := make(chan M.Metadata, 1)
	service, err := NewService(Config{
		Handshake: target.Listener.Addr().String(), Password: "integration-password",
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
	if _, err = client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 4)
	if _, err = io.ReadFull(client, payload); err != nil || string(payload) != "pong" {
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
		if !errors.Is(err, errRestlsDownstream) {
			t.Fatalf("server result = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not propagate downstream result")
	}
}
