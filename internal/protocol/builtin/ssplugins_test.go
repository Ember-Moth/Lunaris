// SPDX-License-Identifier: GPL-3.0-only
package builtin_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	engine "github.com/metacubex/restls-client-go"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/testutil"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/smux"
)

func startSSPlugin(t *testing.T, kind string, options map[string]any, limits model.Limits) running {
	return startConfigured(t, "shadowsocks", kind, false, limits, func(s *model.ListenerSpec) {
		s.CredentialRefs = []string{"one"}
		s.Options = []byte(`{"method":"aes-128-gcm"}`)
		s.Transport.Plugin, _ = json.Marshal(options)
		if kind == "v2ray-plugin" || kind == "gost-plugin" {
			s.Transport.Path = "/proxy"
			s.Transport.Host = "localhost"
		}
	})
}
func TestPluginMuxUnauthenticatedCarrierExpires(t *testing.T) {
	for _, kind := range []string{"v2ray-plugin", "gost-plugin"} {
		t.Run(kind, func(t *testing.T) {
			limits := model.DefaultLimits()
			limits.HandshakeTimeout = 150 * time.Millisecond
			limits.MaxPendingHandshakes = 1
			s := startSSPlugin(t, kind, map[string]any{"mux": true}, limits)
			c := carrierDial(t, s, "ws", false)
			_ = c.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := c.Read(make([]byte, 1)); err == nil {
				t.Fatal("unauthenticated carrier stayed open")
			} else if e, ok := err.(net.Error); ok && e.Timeout() {
				t.Fatal("carrier handshake budget was bypassed")
			}
			c.Close()
		})
	}
}
func TestGostAuthenticatedStreamsSurviveAndIsolateTimeouts(t *testing.T) {
	limits := model.DefaultLimits()
	limits.HandshakeTimeout = 150 * time.Millisecond
	s := startSSPlugin(t, "gost-plugin", map[string]any{"mux": true}, limits)
	cfg := smux.DefaultConfig()
	cfg.KeepAliveDisabled = true
	session, err := smux.Client(carrierDial(t, s, "ws", false), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	target := M.SocksaddrFromNet(testutil.TCPEcho(t))
	open := func() net.Conn {
		stream, err := session.OpenStream()
		if err != nil {
			t.Fatal(err)
		}
		method, err := shadowaead.New("aes-128-gcm", nil, password)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := method.DialConn(stream, target)
		if err != nil {
			t.Fatal(err)
		}
		return conn
	}
	first := open()
	defer first.Close()
	echo(t, first)
	silent, err := session.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	_ = silent.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := silent.Read(make([]byte, 1)); err == nil {
		t.Fatal("silent child survived deadline")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("child deadline did not close stream")
	}
	time.Sleep(2 * limits.HandshakeTimeout)
	echo(t, first)
	second := open()
	defer second.Close()
	echo(t, second)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.instance.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	_ = first.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := first.Read(make([]byte, 1)); err == nil {
		t.Fatal("active stream survived stop")
	}
}
func TestShadowTLSFallbackTargetClosesAtHandshakeDeadline(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	result := make(chan error, 1)
	go func() {
		c, err := target.Accept()
		if err != nil {
			result <- err
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err = io.Copy(io.Discard, c)
		result <- err
	}()
	limits := model.DefaultLimits()
	limits.HandshakeTimeout = 150 * time.Millisecond
	s := startSSPlugin(t, "shadow-tls", map[string]any{"version": 1, "handshake": target.Addr().String()}, limits)
	raw := carrierDial(t, s, "tcp", false)
	defer raw.Close()
	// A TLS prefix selects the ordinary connection path before fallback dialing.
	if _, err := raw.Write([]byte{22}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal("fallback target was not closed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("fallback target outlived handshake")
	}
}

func TestRestlsRetainsTargetAfterAuthentication(t *testing.T) {
	target := httptest.NewUnstartedServer(http.NotFoundHandler())
	target.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	target.StartTLS()
	defer target.Close()
	limits := model.DefaultLimits()
	limits.HandshakeTimeout = 300 * time.Millisecond
	s := startSSPlugin(t, "restls", map[string]any{"password_ref": "one", "dest": target.Listener.Addr().String()}, limits)
	raw := carrierDial(t, s, "tcp", false)
	cfg, err := engine.NewRestlsConfig("localhost", password, "tls13", "", "chrome")
	if err != nil {
		t.Fatal(err)
	}
	cfg.InsecureSkipVerify = true
	cfg.MinVersion = engine.VersionTLS13
	cfg.MaxVersion = engine.VersionTLS13
	secure := engine.UClient(raw, cfg, engine.HelloChrome_Auto)
	if err := secure.HandshakeContext(testutil.Context(t)); err != nil {
		t.Fatal(err)
	}
	method, err := shadowaead.New("aes-128-gcm", nil, password)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := method.DialConn(secure, M.SocksaddrFromNet(testutil.TCPEcho(t)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	echo(t, conn)
	time.Sleep(2 * limits.HandshakeTimeout)
	echo(t, conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.instance.Stop(ctx); err != nil {
		t.Fatal(err)
	}
}
