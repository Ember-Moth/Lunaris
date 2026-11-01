// SPDX-License-Identifier: GPL-3.0-only
package node

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/testutil"
	X "github.com/Ember-Moth/Lunaris/internal/transport/xhttp"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

func TestXHTTPReloadRevokesOldSessions(t *testing.T) {
	input := realConfig(t)
	input.Credentials["a"] = []byte("c8820ed3-e4ee-47ad-a5bd-ece70763e32c")
	s := &input.Config.Listeners[0]
	s.Protocol = "vless"
	s.Network = []string{"tcp"}
	s.Options = []byte(`{}`)
	s.Transport = model.Transport{Type: "xhttp", Path: "/old", XHTTP: &model.XHTTP{Mode: "packet-up", HTTPVersion: "h1"}}
	runtime := startReal(t, input)
	destination := M.SocksaddrFromNet(testutil.TCPEcho(t))
	connect := func(path string) (net.Conn, error) {
		cfg, err := X.Parse("", path, "packet-up", "")
		if err != nil {
			return nil, err
		}
		client := X.NewClient(X.ClientOptions{Context: testutil.Context(t), Config: cfg, Server: fmt.Sprintf("127.0.0.1:%d", s.Port), Dial: func(ctx context.Context, address string, _ *tls.Config) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", address)
		}})
		t.Cleanup(func() { client.Close() })
		raw, err := client.DialContext(testutil.Context(t))
		if err != nil {
			return nil, err
		}
		v, _ := vless.NewClient(string(input.Credentials["a"]), "", logger.NOP())
		return v.DialConn(raw, destination)
	}
	roundtrip := func(c net.Conn) {
		t.Helper()
		_ = c.SetDeadline(time.Now().Add(time.Second))
		if _, err := c.Write([]byte("live")); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil || string(b) != "live" {
			t.Fatal("XHTTP forwarding failed", err)
		}
	}
	old, err := connect("/old")
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	roundtrip(old)
	invalid := cloneConfig(t, input)
	invalid.Config.Listeners[0].Transport.XHTTP.Extra = []byte(`{"unsupported":true}`)
	if _, err = runtime.Apply(context.Background(), invalid); err == nil {
		t.Fatal("invalid XHTTP config applied")
	}
	roundtrip(old)
	changed := cloneConfig(t, input)
	changed.Config.Listeners[0].Transport.Path = "/new"
	result, err := runtime.Apply(context.Background(), changed)
	if err != nil || result.Outcome != "applied" {
		t.Fatal(result, err)
	}
	if _, err = old.Read(make([]byte, 1)); err == nil {
		t.Fatal("old XHTTP session survived reload")
	}
	fresh, err := connect("/new")
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	roundtrip(fresh)
	if rejected, err := connect("/old"); err == nil {
		rejected.Close()
		t.Fatal("old XHTTP path still accepted")
	}
}
