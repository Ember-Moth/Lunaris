// SPDX-License-Identifier: GPL-3.0-only
package outbound_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/egress"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/node"
	"github.com/Ember-Moth/Lunaris/internal/outbound"
	"github.com/Ember-Moth/Lunaris/internal/protocol/builtin"
	"github.com/Ember-Moth/Lunaris/internal/testutil"
	M "github.com/sagernet/sing/common/metadata"
)

func TestShadowsocksMethodsTCPAndUDP(t *testing.T) {
	for _, caps := range outbound.NewRegistry().Capabilities() {
		if caps.Protocol != "shadowsocks" {
			continue
		}
		for _, method := range caps.Methods {
			t.Run(method, func(t *testing.T) {
				secret := "disposable-outbound-password"
				if len(method) > 4 && method[:4] == "2022" {
					size := 32
					if method == "2022-blake3-aes-128-gcm" {
						size = 16
					}
					secret = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{42}, size))
				}
				listener, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				port := M.SocksaddrFromNet(listener.Addr()).Port
				listener.Close()
				registry, err := builtin.NewRegistry()
				if err != nil {
					t.Fatal(err)
				}
				config := &model.RuntimeConfig{Config: model.NodeConfig{SchemaVersion: 1, Limits: model.DefaultLimits(), Listeners: []model.ListenerSpec{{ID: "ss", Enabled: true, Protocol: "shadowsocks", Address: "127.0.0.1", Port: port, Network: []string{"tcp", "udp"}, CredentialRefs: []string{"key"}, Options: []byte(fmt.Sprintf(`{"method":%q}`, method))}}}, Credentials: map[string][]byte{"key": []byte(secret)}}
				runtime, err := node.Start(context.Background(), config, registry, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer runtime.Close(context.Background())
				client, err := outbound.NewRegistry().Build(context.Background(), model.OutboundSpec{ID: "upstream", Protocol: "shadowsocks", Address: "127.0.0.1", Port: port, CredentialRef: "key", Options: []byte(fmt.Sprintf(`{"method":%q}`, method))}, config.Credentials, &egress.Direct{}, config.Config.Limits)
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close(context.Background())
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				connection, err := client.DialContext(ctx, "tcp", M.SocksaddrFromNet(testutil.TCPEcho(t)))
				if err != nil {
					t.Fatal(err)
				}
				defer connection.Close()
				connection.SetDeadline(time.Now().Add(time.Second))
				payload := bytes.Repeat([]byte("outbound"), 4096)
				if _, err := connection.Write(payload); err != nil {
					t.Fatal(err)
				}
				response := make([]byte, len(payload))
				if _, err := io.ReadFull(connection, response); err != nil || !bytes.Equal(response, payload) {
					t.Fatal("TCP failed", err)
				}
				target := testutil.UDPEcho(t)
				socket, err := client.ListenPacket(ctx, M.SocksaddrFromNet(target))
				if err != nil {
					t.Fatal(err)
				}
				defer socket.Close()
				socket.SetDeadline(time.Now().Add(time.Second))
				if _, err := socket.WriteTo([]byte("packet"), target); err != nil {
					t.Fatal(err)
				}
				var b [64]byte
				n, source, err := socket.ReadFrom(b[:])
				if err != nil || string(b[:n]) != "packet" || source.String() != target.String() {
					t.Fatal("UDP failed", err, source)
				}
			})
		}
	}
}
