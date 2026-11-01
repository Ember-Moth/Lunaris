// SPDX-License-Identifier: GPL-3.0-only
package transport

import (
	"bytes"
	"context"
	"encoding/base64"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/coder/websocket"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestPluginEarlyDataExpandsBoundedHTTPHeaderBudget(t *testing.T) {
	payload := bytes.Repeat([]byte("e"), 16384)
	result := make(chan error, 1)
	binding := Binding{Stream: &StreamHandler{Serve: func(ctx context.Context, c net.Conn, _ M.Socksaddr, close N.CloseHandlerFunc) error {
		got := make([]byte, len(payload))
		_, err := io.ReadFull(c, got)
		if err == nil && !bytes.Equal(got, payload) {
			err = io.ErrUnexpectedEOF
		}
		ReleaseHandshake(ctx)
		result <- err
		close(err)
		return err
	}}}
	server, err := (PluginFactory{Kind: "v2ray-plugin"}).Build(ResolvedSpec{Address: "127.0.0.1", Limits: model.DefaultLimits(), Transport: model.Transport{Type: "v2ray-plugin", Path: "/proxy?ed=16384", Plugin: []byte(`{"mux":false}`)}}, binding)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Stop(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := server.Start(ctx); err != nil {
		t.Fatal(err)
	}
	address := server.(interface{ Addr() net.Addr }).Addr().String()
	conn, _, err := websocket.Dial(ctx, "ws://"+address+"/proxy", &websocket.DialOptions{HTTPHeader: http.Header{"Sec-WebSocket-Protocol": {base64.RawURLEncoding.EncodeToString(payload)}}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
