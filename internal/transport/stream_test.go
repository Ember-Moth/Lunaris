// SPDX-License-Identifier: GPL-3.0-only
package transport

import (
	"context"
	"errors"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/coder/websocket"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"io"
	"net"
	"testing"
	"time"
)

func TestWebSocketRejectionReleasesCarrierWithoutPeerClose(t *testing.T) {
	limits := model.DefaultLimits()
	limits.MaxConnections = 1
	s := NewStream(model.ListenerSpec{Address: "127.0.0.1", Transport: model.Transport{Type: "ws", Path: "/proxy"}}, limits)
	s.Serve = func(_ context.Context, c net.Conn, _ M.Socksaddr, _ N.CloseHandlerFunc) error {
		var b [1]byte
		_, _ = io.ReadFull(c, b[:])
		return errors.New("invalid protocol credential")
	}
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
