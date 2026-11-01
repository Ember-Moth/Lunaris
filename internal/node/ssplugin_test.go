// SPDX-License-Identifier: GPL-3.0-only
package node

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/testutil"
	engine "github.com/metacubex/restls-client-go"
	ss "github.com/sagernet/sing-shadowsocks/shadowaead"
	M "github.com/sagernet/sing/common/metadata"
)

func TestShadowsocksPluginSecretRotation(t *testing.T) {
	target := httptest.NewTLSServer(http.NotFoundHandler())
	defer target.Close()
	input := realConfig(t)
	input.Credentials["plugin"] = []byte("initial-plugin-secret")
	input.Config.Listeners[0].Network = []string{"tcp"}
	input.Config.Listeners[0].Transport.Type = "restls"
	input.Config.Listeners[0].Transport.Plugin, _ = json.Marshal(map[string]any{"dest": target.Listener.Addr().String(), "password_ref": "plugin"})
	runtime := startReal(t, input)
	dst := M.SocksaddrFromNet(testutil.TCPEcho(t))
	connect := func(index int, password string) (net.Conn, error) {
		spec := input.Config.Listeners[index]
		raw, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", spec.Port), time.Second)
		if err != nil {
			return nil, err
		}
		_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
		var carrier net.Conn = raw
		if password != "" {
			cfg, e := engine.NewRestlsConfig("localhost", password, "tls13", "", "chrome")
			if e != nil {
				raw.Close()
				return nil, e
			}
			cfg.InsecureSkipVerify = true
			cfg.MinVersion = engine.VersionTLS13
			cfg.MaxVersion = engine.VersionTLS13
			secured := engine.UClient(raw, cfg, engine.HelloChrome_Auto)
			if err := secured.HandshakeContext(testutil.Context(t)); err != nil {
				raw.Close()
				return nil, err
			}
			carrier = secured
		}
		method, err := ss.New("aes-128-gcm", nil, string(input.Credentials[spec.CredentialRefs[0]]))
		if err != nil {
			raw.Close()
			return nil, err
		}
		c, err := method.DialConn(carrier, dst)
		if err != nil {
			raw.Close()
		}
		return c, err
	}
	exchange := func(c net.Conn) error {
		_ = c.SetDeadline(time.Now().Add(time.Second))
		if _, err := c.Write([]byte("live")); err != nil {
			return err
		}
		b := make([]byte, 4)
		_, err := io.ReadFull(c, b)
		if err == nil && string(b) != "live" {
			return fmt.Errorf("wrong payload")
		}
		return err
	}
	old, err := connect(0, "initial-plugin-secret")
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	other, err := connect(1, "")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	for _, c := range []net.Conn{old, other} {
		if err := exchange(c); err != nil {
			t.Fatal(err)
		}
	}
	invalid := cloneConfig(t, input)
	invalid.Credentials["plugin"] = nil
	if _, err := runtime.Apply(context.Background(), invalid); err == nil {
		t.Fatal("invalid plugin secret applied")
	}
	if err := exchange(old); err != nil {
		t.Fatal("invalid apply interrupted live session", err)
	}
	changed := cloneConfig(t, input)
	changed.Credentials["plugin"] = []byte("replacement-plugin-secret")
	result, err := runtime.Apply(context.Background(), changed)
	if err != nil || result.Outcome != "applied" {
		t.Fatal(result, err)
	}
	_ = old.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := old.Read(make([]byte, 1)); err == nil {
		t.Fatal("old plugin session survived rotation")
	}
	if err := exchange(other); err != nil {
		t.Fatal("unrelated listener interrupted", err)
	}
	current, err := connect(0, "replacement-plugin-secret")
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	if err := exchange(current); err != nil {
		t.Fatal(err)
	}
	if rejected, err := connect(0, "initial-plugin-secret"); err == nil {
		defer rejected.Close()
		if err := exchange(rejected); err == nil {
			t.Fatal("old plugin secret accepted")
		}
	}
}
