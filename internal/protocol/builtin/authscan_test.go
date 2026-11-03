// SPDX-License-Identifier: GPL-3.0-only
package builtin_test

import (
	"bytes"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/testutil"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	vmess "github.com/sagernet/sing-vmess"
	M "github.com/sagernet/sing/common/metadata"
)

func TestAuthscanMultipleUsersTCP(t *testing.T) {
	for _, kind := range []string{"shadowsocks", "vmess"} {
		t.Run(kind, func(t *testing.T) {
			carrier := "tcp"
			if kind == "shadowsocks" {
				carrier = "native"
			}
			s := startConfigured(t, kind, carrier, false, model.DefaultLimits(), func(spec *model.ListenerSpec) {
				if kind == "shadowsocks" {
					spec.Options = []byte(`{"method":"aes-128-gcm"}`)
				}
			})
			destination := M.SocksaddrFromNet(testutil.TCPEcho(t))
			for _, secret := range []string{password, "another-password", password, "another-password"} {
				raw := carrierDial(t, s, carrier, false)
				var conn net.Conn
				var err error
				if kind == "shadowsocks" {
					method, _ := shadowaead.New("aes-128-gcm", nil, secret)
					conn, err = method.DialConn(raw, destination)
				} else {
					id := userID
					if secret != "" && secret != password {
						id = "ab20e8ef-131d-448d-a58d-b6d81e25073b"
					}
					client, _ := vmess.NewClient(id, "aes-128-gcm", 0)
					conn, err = client.DialConn(raw, destination)
				}
				if err != nil {
					raw.Close()
					t.Fatal(err)
				}
				echo(t, conn)
				conn.Close()
			}
		})
	}
}

func TestSnellMultiplePSKs(t *testing.T) {
	for _, tc := range []struct {
		version    int
		obfs, mode string
	}{{5, "none", ""}, {5, "http", ""}, {5, "tls", ""}, {6, "", "default"}, {6, "", "unshaped"}} {
		options, _ := json.Marshal(map[string]any{"version": tc.version, "obfs": tc.obfs, "mode": tc.mode})
		t.Run(string(options), func(t *testing.T) {
			s := startConfigured(t, "snell", "tcp", false, model.DefaultLimits(), func(spec *model.ListenerSpec) { spec.Options = options })
			target := testutil.TCPEcho(t)
			for _, secret := range []string{password, "another-password", password, "another-password"} {
				client := snellClient(t, s, tc.version, tc.obfs, tc.mode, []byte(secret), true)
				conn, err := client.DialContext(testutil.Context(t), M.SocksaddrFromNet(target))
				if err != nil {
					t.Fatal(err)
				}
				echo(t, conn)
				conn.Close()
				raw, err := net.Dial("tcp", s.addr.String())
				if err != nil {
					t.Fatal(err)
				}
				raw.SetDeadline(time.Now().Add(2 * time.Second))
				packet, err := client.DialPacketConn(raw)
				if err != nil {
					raw.Close()
					t.Fatal(err)
				}
				payload := []byte("multi-user-UDP")
				if _, err = packet.WriteTo(payload, testutil.UDPEcho(t)); err != nil {
					packet.Close()
					t.Fatal(err)
				}
				received := make([]byte, 1024)
				n, _, err := packet.ReadFrom(received)
				packet.Close()
				if err != nil || !bytes.Equal(payload, received[:n]) {
					t.Fatal("multi-user reply", err)
				}
			}
		})
	}
}
