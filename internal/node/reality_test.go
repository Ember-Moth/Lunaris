// SPDX-License-Identifier: GPL-3.0-only
package node

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/testutil"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

func TestRealityKeyRotationRevokesSessions(t *testing.T) {
	cert, _ := testutil.Certificate(t)
	pair, err := tls.X509KeyPair(cert.Certificate, cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	target := httptest.NewUnstartedServer(http.NotFoundHandler())
	target.EnableHTTP2 = true
	target.Config.ErrorLog = log.New(io.Discard, "", 0)
	target.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}
	target.StartTLS()
	defer target.Close()
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	next, _ := ecdh.X25519().GenerateKey(rand.Reader)
	input := realConfig(t)
	input.Credentials = map[string][]byte{"a": []byte("c8820ed3-e4ee-47ad-a5bd-ece70763e32c"), "b": []byte("c8820ed3-e4ee-47ad-a5bd-ece70763e32c"), "reality-key": []byte(base64.RawURLEncoding.EncodeToString(key.Bytes()))}
	for i := range input.Config.Listeners {
		s := &input.Config.Listeners[i]
		s.Protocol = "vless"
		s.Network = []string{"tcp"}
		s.Options = []byte("{}")
	}
	input.Config.Listeners[0].Transport = model.Transport{Type: "reality", Reality: &model.Reality{Target: target.Listener.Addr().String(), ServerNames: []string{"localhost"}, PrivateKeyRef: "reality-key", ShortIDs: []string{"0102030405060708"}}}
	runtime := startReal(t, input)
	echo := M.SocksaddrFromNet(testutil.TCPEcho(t))
	connect := func(index int, key *ecdh.PrivateKey) (net.Conn, error) {
		spec := input.Config.Listeners[index]
		raw, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", spec.Port), time.Second)
		if err != nil {
			return nil, err
		}
		_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
		var carrier net.Conn = raw
		if key != nil {
			carrier, err = testutil.RealityClient(context.Background(), raw, key.PublicKey().Bytes(), []byte{1, 2, 3, 4, 5, 6, 7, 8}, "localhost")
			if err != nil {
				raw.Close()
				return nil, err
			}
		}
		client, _ := vless.NewClient(string(input.Credentials["a"]), "", logger.NOP())
		conn, err := client.DialConn(carrier, echo)
		if err != nil {
			raw.Close()
		}
		return conn, err
	}
	roundtrip := func(c net.Conn) {
		t.Helper()
		_ = c.SetDeadline(time.Now().Add(time.Second))
		if _, err := c.Write([]byte("keep")); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil || string(b) != "keep" {
			t.Fatal("forwarding failed", err)
		}
	}
	old, err := connect(0, key)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	other, err := connect(1, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	roundtrip(old)
	roundtrip(other)
	invalid := cloneConfig(t, input)
	invalid.Credentials["reality-key"] = []byte("invalid-key")
	if _, err = runtime.Apply(context.Background(), invalid); err == nil {
		t.Fatal("invalid REALITY key applied")
	}
	roundtrip(old)
	changed := cloneConfig(t, input)
	changed.Credentials["reality-key"] = []byte(base64.RawURLEncoding.EncodeToString(next.Bytes()))
	result, err := runtime.Apply(context.Background(), changed)
	if err != nil || result.Outcome != "applied" {
		t.Fatal("key rotation failed", err)
	}
	_ = old.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = old.Read(make([]byte, 1)); err == nil {
		t.Fatal("old REALITY session survived rotation")
	}
	roundtrip(other)
	replacement, err := connect(0, next)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	roundtrip(replacement)
	rejected, err := connect(0, key)
	if err == nil {
		rejected.Close()
		t.Fatal("old REALITY key still authenticated")
	}
}
