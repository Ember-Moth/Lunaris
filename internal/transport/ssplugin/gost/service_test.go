// SPDX-License-Identifier: GPL-3.0-or-later
// Adapted from Polaris; see THIRD_PARTY_NOTICES.md.
package gost

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/smux"
)

type echoService struct{}

type blockingService struct {
	started chan struct{}
	once    sync.Once
}

func (service *blockingService) NewConnection(ctx context.Context, _ net.Conn, _ M.Metadata) error {
	service.once.Do(func() { close(service.started) })
	<-ctx.Done()
	return ctx.Err()
}

type returnService struct{}

func (returnService) NewConnection(context.Context, net.Conn, M.Metadata) error { return nil }

type deadlineTrackingConn struct {
	net.Conn
	cleared chan struct{}
	once    sync.Once
}

func (conn *deadlineTrackingConn) SetReadDeadline(deadline time.Time) error {
	if deadline.IsZero() {
		conn.once.Do(func() { close(conn.cleared) })
	}
	return conn.Conn.SetReadDeadline(deadline)
}

func (echoService) NewConnection(_ context.Context, conn net.Conn, _ M.Metadata) error {
	defer func() { _ = conn.Close() }()
	payload := make([]byte, 4)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return err
	}
	_, err := conn.Write([]byte(strings.ToUpper(string(payload))))
	return err
}

func TestServiceMultiplexesGostStreams(t *testing.T) {
	serverRaw, clientRaw := net.Pipe()
	if err := serverRaw.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	tracked := &deadlineTrackingConn{Conn: serverRaw, cleared: make(chan struct{})}
	service := NewService(Config{Mux: true}, echoService{}, nil)
	result := make(chan error, 1)
	go func() { result <- service.NewConnection(context.Background(), tracked, M.Metadata{}) }()
	select {
	case <-tracked.cleared:
	case <-time.After(time.Second):
		t.Fatal("service did not clear the carrier read deadline")
	}

	config := smux.DefaultConfig()
	config.KeepAliveDisabled = true
	client, err := smux.Client(clientRaw, config)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{"ping", "pong"} {
		stream, err := client.OpenStream()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := stream.Write([]byte(input)); err != nil {
			t.Fatal(err)
		}
		payload := make([]byte, 4)
		if _, err := io.ReadFull(stream, payload); err != nil {
			t.Fatal(err)
		}
		if string(payload) != strings.ToUpper(input) {
			t.Fatalf("response = %q", payload)
		}
		_ = stream.Close()
	}
	_ = client.Close()
	_ = clientRaw.Close()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("service did not stop")
	}
}

func TestServiceLimitsGostStreams(t *testing.T) {
	serverRaw, clientRaw := net.Pipe()
	blocking := &blockingService{started: make(chan struct{})}
	service := NewService(Config{Mux: true, MaxStreams: 1, MaxActiveStreams: 1}, blocking, nil)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- service.NewConnection(ctx, serverRaw, M.Metadata{}) }()
	client, err := smux.Client(clientRaw, smux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	first, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-blocking.started:
	case <-time.After(time.Second):
		t.Fatal("first virtual stream did not start")
	}
	second, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	_ = second.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = second.Read(make([]byte, 1)); err == nil {
		t.Fatal("second stream was not rejected")
	}
	cancel()
	_ = first.Close()
	_ = second.Close()
	_ = client.Close()
	_ = clientRaw.Close()
	select {
	case <-result:
	case <-time.After(time.Second):
		t.Fatal("service did not stop")
	}
}

func TestServiceClosesGostStreamAfterCleanReturn(t *testing.T) {
	serverRaw, clientRaw := net.Pipe()
	service := NewService(Config{Mux: true}, returnService{}, nil)
	result := make(chan error, 1)
	go func() { result <- service.NewConnection(context.Background(), serverRaw, M.Metadata{}) }()
	client, err := smux.Client(clientRaw, smux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	stream, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = stream.Read(make([]byte, 1)); err == nil {
		t.Fatal("stream remained open after downstream returned")
	}
	_ = stream.Close()
	_ = client.Close()
	_ = clientRaw.Close()
	select {
	case <-result:
	case <-time.After(time.Second):
		t.Fatal("service did not stop")
	}
}
