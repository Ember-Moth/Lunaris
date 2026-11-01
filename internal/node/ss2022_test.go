// SPDX-License-Identifier: GPL-3.0-only
package node

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/testutil"
	ss "github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	M "github.com/sagernet/sing/common/metadata"
)

func TestSS2022ServerKeyRotation(t *testing.T) {
	key := func(b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 16)) }
	input := realConfig(t)
	input.Credentials["a"] = []byte(key(1))
	input.Credentials["server"] = []byte(key(2))
	input.Config.Listeners[0].Options = []byte(`{"method":"2022-blake3-aes-128-gcm","server_key_ref":"server"}`)
	runtime := startReal(t, input)
	dst := M.SocksaddrFromNet(testutil.TCPEcho(t))
	connect := func(master string) net.Conn {
		t.Helper()
		spec := input.Config.Listeners[0]
		raw, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", spec.Port))
		if err != nil {
			t.Fatal(err)
		}
		_ = raw.SetDeadline(time.Now().Add(time.Second))
		client, err := ss.NewWithPassword("2022-blake3-aes-128-gcm", master+":"+key(1), nil)
		if err != nil {
			t.Fatal(err)
		}
		c, err := client.DialConn(raw, dst)
		if err != nil {
			raw.Close()
			t.Fatal(err)
		}
		return c
	}
	check := func(c net.Conn) {
		t.Helper()
		if _, err := c.Write([]byte("live")); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil || string(b) != "live" {
			t.Fatal("stream failed", err)
		}
	}
	old := connect(key(2))
	defer old.Close()
	check(old)
	invalid := cloneConfig(t, input)
	invalid.Credentials["server"] = []byte("invalid")
	if _, err := runtime.Apply(context.Background(), invalid); err == nil {
		t.Fatal("invalid key accepted")
	}
	check(old)
	changed := cloneConfig(t, input)
	changed.Credentials["server"] = []byte(key(3))
	result, err := runtime.Apply(context.Background(), changed)
	if err != nil || result.Outcome != "applied" {
		t.Fatal(result, err)
	}
	if _, err := old.Read(make([]byte, 1)); err == nil {
		t.Fatal("old session survived server key rotation")
	}
	current := connect(key(3))
	defer current.Close()
	check(current)
	rejected := connect(key(2))
	defer rejected.Close()
	_, _ = rejected.Write([]byte("reject"))
	if _, err := rejected.Read(make([]byte, 1)); err == nil {
		t.Fatal("old master key accepted")
	}
}
