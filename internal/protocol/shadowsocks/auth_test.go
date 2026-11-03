// SPDX-License-Identifier: GPL-3.0-only
package shadowsocks

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/egress"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/Ember-Moth/Lunaris/internal/relay"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
)

func TestMultipleUsersShareUDPSourceWithoutSharingKeys(t *testing.T) {
	for _, method := range Methods {
		t.Run(method, func(t *testing.T) {
			limits := model.DefaultLimits()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			flow := relay.New(ctx, &egress.Direct{}, limits)
			spec := model.ListenerSpec{ID: "multi", Protocol: "shadowsocks", Address: "127.0.0.1", CredentialRefs: []string{"alice", "bob"}, Options: []byte(`{"method":"` + method + `"}`)}
			s, err := buildTestServer(t, protocol.ResolvedListenerSpec{Spec: spec, Limits: limits, Credentials: map[string][]byte{"alice": []byte("alice-secret"), "bob": []byte("bob-secret")}}, protocol.Dependencies{Handler: flow})
			if err != nil {
				t.Fatal(err)
			}
			if err = s.Start(ctx); err != nil {
				t.Fatal(err)
			}
			defer func() {
				cancel()
				cleanup, stop := context.WithTimeout(context.Background(), time.Second)
				defer stop()
				if err := s.Stop(cleanup); err != nil {
					t.Error(err)
				}
				if err := flow.Close(cleanup); err != nil {
					t.Error(err)
				}
			}()
			raw, err := net.Dial("udp", s.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			raw.SetDeadline(time.Now().Add(3 * time.Second))
			target := udpEcho(t)
			for _, secret := range []string{"alice-secret", "bob-secret", "alice-secret", "bob-secret"} {
				m, _ := shadowaead.New(method, nil, secret)
				pc := m.DialPacketConn(raw)
				payload := []byte(secret + "-payload")
				if _, err = pc.WriteTo(payload, target); err != nil {
					t.Fatal(err)
				}
				received := make([]byte, 1500)
				n, _, err := pc.ReadFrom(received)
				if err != nil || !bytes.Equal(received[:n], payload) {
					t.Fatal("wrong user reply key", err)
				}
			}
			s.mu.Lock()
			sessions := len(s.sessions)
			s.mu.Unlock()
			if sessions != 2 {
				t.Fatalf("sessions=%d, expected distinct user associations", sessions)
			}
		})
	}
}
