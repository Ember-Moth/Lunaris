// SPDX-License-Identifier: GPL-3.0-only
package shadowsocks

import (
	"bytes"
	"github.com/Ember-Moth/Lunaris/internal/egress"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	"net"
	"testing"
	"time"
)

func TestRejectReflectedServerUDPResponse(t *testing.T) {
	for _, methodName := range Methods {
		t.Run(methodName, func(t *testing.T) {
			target := udpEcho(t)
			server, _ := startServer(t, methodName, model.DefaultLimits(), &egress.Direct{})
			method, _ := shadowaead.New(methodName, nil, testPassword)
			var request []byte
			encoder := method.DialPacketConn(&datagramConn{write: func(p []byte) (int, error) { request = bytes.Clone(p); return len(p), nil }})
			if _, err := encoder.WriteTo([]byte("reflection-audit"), target); err != nil {
				t.Fatal(err)
			}
			client, err := net.Dial("udp", server.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			client.SetDeadline(time.Now().Add(time.Second))
			if _, err = client.Write(request); err != nil {
				t.Fatal(err)
			}
			response := make([]byte, 1500)
			n, err := client.Read(response)
			if err != nil {
				t.Fatal(err)
			}
			response = response[:n]
			reflected, err := net.Dial("udp", server.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer reflected.Close()
			reflected.SetDeadline(time.Now().Add(150 * time.Millisecond))
			if _, err = reflected.Write(response); err != nil {
				t.Fatal(err)
			}
			if n, err = reflected.Read(make([]byte, 1500)); err == nil {
				t.Fatalf("captured server response was accepted as a new client request and returned %d encrypted bytes", n)
			}
		})
	}
}
