// SPDX-License-Identifier: GPL-3.0-only
package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/coder/websocket"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestWebSocketRejectionReleasesCarrierWithoutPeerClose(t *testing.T) {
	limits := model.DefaultLimits()
	limits.MaxConnections = 1
	binding := Binding{Stream: &StreamHandler{Serve: func(_ context.Context, c net.Conn, _ M.Socksaddr, _ N.CloseHandlerFunc) error {
		var b [1]byte
		_, _ = io.ReadFull(c, b[:])
		return errors.New("invalid protocol credential")
	}}}
	instance, err := (WebSocketFactory{}).Build(ResolvedSpec{Address: "127.0.0.1", Transport: model.Transport{Type: "ws", Path: "/proxy"}, Limits: limits}, binding)
	if err != nil {
		t.Fatal(err)
	}
	s := instance.(*socketServer)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(ctx)
	ws, _, err := websocket.Dial(ctx, "ws://"+s.Addr().String()+"/proxy", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	if err := ws.Write(ctx, websocket.MessageBinary, []byte{1}); err != nil {
		t.Fatal(err)
	}
	// This peer deliberately never reads or acknowledges WebSocket Close frames.
	end := time.Now().Add(500 * time.Millisecond)
	for {
		s.mu.Lock()
		active := len(s.conns)
		s.mu.Unlock()
		if active == 0 {
			break
		}
		if time.Now().After(end) {
			t.Fatal("rejected carrier waits for WebSocket close acknowledgement")
		}
		time.Sleep(time.Millisecond)
	}
	if err := s.Stop(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestPacketCleanupContinuesAfterStopDeadline(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	handler := &PacketHandler{Serve: func(ctx context.Context, _ net.PacketConn) error { <-ctx.Done(); return ctx.Err() }, Close: func(context.Context) error { close(entered); <-release; return nil }}
	instance, err := (NativeFactory{}).Build(ResolvedSpec{Address: "127.0.0.1", Network: []string{"udp"}, Limits: model.DefaultLimits()}, Binding{Packet: handler})
	if err != nil {
		t.Fatal(err)
	}
	if err = instance.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err = instance.Stop(cleanup); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Stop did not bound its wait: %v", err)
	}
	<-entered
	close(release)
	retry, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err = instance.Stop(retry); err != nil {
		t.Fatalf("completed cleanup not acknowledged on retry: %v", err)
	}
}
