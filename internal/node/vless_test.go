// SPDX-License-Identifier: GPL-3.0-only
package node

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	vless "github.com/Ember-Moth/Lunaris/internal/protocol/vless/wire"
	"github.com/Ember-Moth/Lunaris/internal/protocol/vless/wire/encryption"
	"github.com/Ember-Moth/Lunaris/internal/testutil"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

func TestVLESSDecryptionRotationRevokesSessions(t *testing.T) {
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	next, _ := ecdh.X25519().GenerateKey(rand.Reader)
	input := realConfig(t)
	input.Credentials = map[string][]byte{"a": []byte("c8820ed3-e4ee-47ad-a5bd-ece70763e32c"), "b": []byte("c8820ed3-e4ee-47ad-a5bd-ece70763e32c"), "enc": []byte("mlkem768x25519plus.native.600s.100-35-35." + base64.RawURLEncoding.EncodeToString(key.Bytes()))}
	for i := range input.Config.Listeners {
		s := &input.Config.Listeners[i]
		s.Protocol = "vless"
		s.Network = []string{"tcp"}
		s.Options = []byte("{}")
	}
	input.Config.Listeners[0].Options = []byte(`{"flow":"xtls-rprx-vision","decryption_ref":"enc"}`)
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
			config, e := encryption.ParseClientConfig("mlkem768x25519plus.native.1rtt.100-35-35." + base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()))
			if e != nil {
				return nil, e
			}
			encrypted, e := config.NewInstance()
			if e != nil {
				return nil, e
			}
			carrier, err = encrypted.Handshake(raw)
			if err != nil {
				raw.Close()
				return nil, err
			}
		}
		flow := ""
		if key != nil {
			flow = vless.FlowVision
		}
		client, _ := vless.NewClient(string(input.Credentials["a"]), flow, logger.NOP())
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
	invalid.Credentials["enc"] = []byte("invalid-key")
	if _, err = runtime.Apply(context.Background(), invalid); err == nil {
		t.Fatal("invalid VLESS Encryption key applied")
	}
	roundtrip(old)
	changed := cloneConfig(t, input)
	changed.Credentials["enc"] = []byte("mlkem768x25519plus.native.600s.100-35-35." + base64.RawURLEncoding.EncodeToString(next.Bytes()))
	result, err := runtime.Apply(context.Background(), changed)
	if err != nil || result.Outcome != "applied" {
		t.Fatal("key rotation failed", err)
	}
	_ = old.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = old.Read(make([]byte, 1)); err == nil {
		t.Fatal("old VLESS Encryption session survived rotation")
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
		t.Fatal("old VLESS Encryption key still authenticated")
	}
}
