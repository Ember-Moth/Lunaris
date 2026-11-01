// SPDX-License-Identifier: GPL-3.0-only
package builtin_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/egress"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/Ember-Moth/Lunaris/internal/protocol/builtin"
	wire "github.com/Ember-Moth/Lunaris/internal/protocol/vless/wire"
	"github.com/Ember-Moth/Lunaris/internal/protocol/vless/wire/encryption"
	"github.com/Ember-Moth/Lunaris/internal/relay"
	"github.com/Ember-Moth/Lunaris/internal/testutil"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

func encryptedVLESS(t *testing.T, carrier string, limits model.Limits) (running, *encryption.ClientInstance) {
	t.Helper()
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	config := "mlkem768x25519plus.native.600s.100-35-35." + base64.RawURLEncoding.EncodeToString(key.Bytes())
	clientConfig, err := encryption.ParseClientConfig("mlkem768x25519plus.native.0rtt.100-35-35." + base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	client, err := clientConfig.NewInstance()
	if err != nil {
		t.Fatal(err)
	}
	registry, _ := builtin.NewRegistry()
	ctx := testutil.Context(t)
	flow := relay.New(ctx, &egress.Direct{}, limits)
	options, _ := json.Marshal(map[string]string{"flow": wire.FlowVision, "decryption_ref": "enc"})
	spec := model.ListenerSpec{ID: "encrypted", Enabled: true, Protocol: "vless", Address: "127.0.0.1", CredentialRefs: []string{"uuid"}, Options: options, Transport: model.Transport{Type: carrier}}
	if carrier == "xhttp" {
		spec.Transport.Path = "/xhttp"
		spec.Transport.XHTTP = &model.XHTTP{HTTPVersion: "h1", Mode: "stream-one"}
	}
	instance, err := registry.Build(protocol.ResolvedListenerSpec{Spec: spec, Limits: limits, Credentials: map[string][]byte{"uuid": []byte(userID), "enc": []byte(config)}}, protocol.Dependencies{Handler: flow, Logger: logger.NOP()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := instance.Stop(ctx); err != nil {
			t.Error(err)
		}
		if err := flow.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	if err := instance.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return running{instance: instance, addr: instance.(interface{ Addr() net.Addr }).Addr(), flow: flow}, client
}

func TestVLESSEncryptedAuthenticationAndResumption(t *testing.T) {
	s, enc := encryptedVLESS(t, "tcp", model.DefaultLimits())
	dst := M.SocksaddrFromNet(testutil.TCPEcho(t))
	for _, identity := range []string{userID, "ab20e8ef-131d-448d-a58d-b6d81e25073b", userID} {
		raw := carrierDial(t, s, "tcp", false)
		carrier, err := enc.Handshake(raw)
		if err != nil {
			t.Fatal(err)
		}
		client, _ := wire.NewClient(identity, wire.FlowVision, logger.NOP())
		c, err := client.DialConn(carrier, dst)
		if err != nil {
			t.Fatal(err)
		}
		if identity == userID {
			echo(t, c)
		} else {
			c.Write([]byte("reject"))
			if _, err := c.Read(make([]byte, 6)); err == nil {
				t.Fatal("wrong UUID accepted")
			}
		}
		c.Close()
	}
	for _, flow := range []string{"", wire.FlowVision} {
		// Missing encryption cannot reach the authenticated relay.
		raw := carrierDial(t, s, "tcp", false)
		request := wire.NewConn(raw, [16]byte{}, 1, dst, flow)
		_ = request.SetDeadline(time.Now().Add(time.Second))
		request.Write([]byte("plaintext"))
		if _, err := request.Read(make([]byte, 1)); err == nil {
			t.Fatal("unencrypted VLESS accepted")
		}
		request.Close()
	}
	// A valid encryption handshake does not authorize a mismatching VLESS flow.
	raw := carrierDial(t, s, "tcp", false)
	carrier, err := enc.Handshake(raw)
	if err != nil {
		t.Fatal(err)
	}
	client, _ := wire.NewClient(userID, "", logger.NOP())
	c, err := client.DialConn(carrier, dst)
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte("flow"))
	if _, err := c.Read(make([]byte, 4)); err == nil {
		t.Fatal("wrong flow accepted")
	}
	c.Close()
}

func TestVLESSPendingHandshakeDeadlineAndStop(t *testing.T) {
	limits := model.DefaultLimits()
	limits.HandshakeTimeout = 150 * time.Millisecond
	limits.MaxPendingHandshakes = 1
	s, enc := encryptedVLESS(t, "tcp", limits)
	raw := carrierDial(t, s, "tcp", false)
	_ = raw.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := raw.Read(make([]byte, 1)); err == nil {
		t.Fatal("silent handshake survived deadline")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("carrier deadline did not close socket")
	}
	raw.Close()
	raw = carrierDial(t, s, "tcp", false)
	carrier, err := enc.Handshake(raw)
	if err != nil {
		t.Fatal("admission slot was not released", err)
	}
	client, _ := wire.NewClient(userID, wire.FlowVision, logger.NOP())
	c, err := client.DialConn(carrier, M.SocksaddrFromNet(testutil.TCPEcho(t)))
	if err != nil {
		t.Fatal(err)
	}
	echo(t, c)
	stalled := carrierDial(t, s, "tcp", false)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.instance.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	for _, conn := range []net.Conn{c, stalled} {
		conn.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := conn.Read(make([]byte, 1)); err == nil {
			t.Fatal("connection survived stop")
		}
		conn.Close()
	}
}

func TestVLESSXUDPDeadline(t *testing.T) {
	s := startConfigured(t, "vless", "tcp", true, model.DefaultLimits(), func(s *model.ListenerSpec) { s.Options = []byte(`{"flow":"xtls-rprx-vision"}`) })
	client, _ := wire.NewClient(userID, wire.FlowVision, logger.NOP())
	udp, err := client.DialEarlyXUDPPacketConn(carrierDial(t, s, "tcp", true), M.SocksaddrFromNet(testutil.UDPEcho(t)))
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	dst := testutil.UDPEcho(t)
	packetEcho(t, udp, dst)
}
