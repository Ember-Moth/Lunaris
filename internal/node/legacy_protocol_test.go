// SPDX-License-Identifier: GPL-3.0-only
package node

import (
	"context"
	"fmt"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/testutil"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	"github.com/sagernet/sing-snell/snellv6"
	M "github.com/sagernet/sing/common/metadata"
	"io"
	"net"
	"testing"
	"time"
)

func TestNewProtocolCredentialRotation(t *testing.T) {
	for _, kind := range []string{"snell", "shadowsocksr"} {
		t.Run(kind, func(t *testing.T) {
			input := realConfig(t)
			s := &input.Config.Listeners[0]
			s.Protocol = model.ProtocolType(kind)
			s.Network = []string{"tcp"}
			s.Transport.Type = ""
			input.Credentials["a"] = []byte("initial-password-credential")
			keyRef := "a"
			if kind == "snell" {
				s.Options = []byte(`{"version":6}`)
			} else {
				s.Options = []byte(`{"method":"aes-128-gcm","protocol":"origin","server_key_ref":"server"}`)
				keyRef = "server"
				input.Credentials[keyRef] = []byte("initial-server-cipher-key")
			}
			runtime := startReal(t, input)
			dst := M.SocksaddrFromNet(testutil.TCPEcho(t))
			connect := func(secret []byte) net.Conn {
				t.Helper()
				raw, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", s.Port))
				if err != nil {
					t.Fatal(err)
				}
				_ = raw.SetDeadline(time.Now().Add(time.Second))
				var c net.Conn
				if kind == "snell" {
					client, e := snellv6.NewClient(snellv6.ClientOptions{PSK: secret})
					if e != nil {
						t.Fatal(e)
					}
					t.Cleanup(func() { client.Close() })
					c, err = client.DialConn(raw, dst)
				} else {
					client, e := shadowaead.New("aes-128-gcm", nil, string(secret))
					if e != nil {
						t.Fatal(e)
					}
					c, err = client.DialConn(raw, dst)
				}
				if err != nil {
					raw.Close()
					t.Fatal(err)
				}
				return c
			}
			roundtrip := func(c net.Conn) {
				t.Helper()
				_, err := c.Write([]byte("live"))
				if err != nil {
					t.Fatal(err)
				}
				b := make([]byte, 4)
				if _, err = io.ReadFull(c, b); err != nil || string(b) != "live" {
					t.Fatal("forwarding", err)
				}
			}
			old := connect(input.Credentials[keyRef])
			defer old.Close()
			roundtrip(old)
			invalid := cloneConfig(t, input)
			invalid.Credentials[keyRef] = nil
			if _, err := runtime.Apply(context.Background(), invalid); err == nil {
				t.Fatal("empty credential applied")
			}
			roundtrip(old)
			changed := cloneConfig(t, input)
			changed.Credentials[keyRef] = []byte("replacement-password-key")
			if result, err := runtime.Apply(context.Background(), changed); err != nil || result.Outcome != "applied" {
				t.Fatal(result, err)
			}
			if _, err := old.Read(make([]byte, 1)); err == nil {
				t.Fatal("old session survived rotation")
			}
			fresh := connect(changed.Credentials[keyRef])
			defer fresh.Close()
			roundtrip(fresh)
		})
	}
}
