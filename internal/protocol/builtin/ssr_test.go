// SPDX-License-Identifier: GPL-3.0-only
package builtin_test

import (
	"bytes"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/testutil"
	"github.com/sagernet/sing-shadowsocks/shadowstream"
	M "github.com/sagernet/sing/common/metadata"
	"io"
	"net"
	"testing"
	"time"
)

func TestSSRClassicOrigin(t *testing.T) {
	s := startConfigured(t, "shadowsocksr", "native", false, model.DefaultLimits(), func(spec *model.ListenerSpec) {
		spec.CredentialRefs = []string{"one"}
		spec.Options = []byte(`{"method":"aes-128-cfb","protocol":"origin"}`)
	})
	method, err := shadowstream.New("aes-128-cfb", nil, password)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Dial("tcp", s.addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	c, err := method.DialConn(raw, M.SocksaddrFromNet(testutil.TCPEcho(t)))
	if err != nil {
		t.Fatal(err)
	}
	echo(t, copyWriteConn{c})
	for i := 0; i < 3; i++ {
		payload := bytes.Repeat([]byte("large-ssr-stream"), 8192)
		_ = c.SetDeadline(time.Now().Add(time.Second))
		if _, err = (copyWriteConn{c}).Write(payload); err != nil {
			t.Fatal(err)
		}
		out := make([]byte, len(payload))
		if _, err = io.ReadFull(c, out); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out, payload) {
			t.Fatal("large SSR payload changed")
		}
	}
	udp, err := net.Dial("udp", s.addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	packetEcho(t, copyWritePacket{method.DialPacketConn(udp)}, testutil.UDPEcho(t))
}

// The legacy upstream client encrypts the caller's Write buffer in place.
// Keep the test's expected plaintext independent of that SDK implementation.
type copyWriteConn struct{ net.Conn }

func (c copyWriteConn) Write(p []byte) (int, error) { return c.Conn.Write(bytes.Clone(p)) }

type copyWritePacket struct{ net.PacketConn }

func (c copyWritePacket) WriteTo(p []byte, a net.Addr) (int, error) {
	return c.PacketConn.WriteTo(bytes.Clone(p), a)
}
