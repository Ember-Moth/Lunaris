// SPDX-License-Identifier: GPL-3.0-only
package snell

import (
	"bytes"
	"context"
	"errors"
	"github.com/Ember-Moth/Lunaris/internal/authscan"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/sagernet/sing-snell/snellv6"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"io"
	"net"
	"testing"
	"time"
)

type memoryConn struct {
	input  *bytes.Reader
	output bytes.Buffer
}

func (c *memoryConn) Read(p []byte) (int, error) {
	if c.input == nil {
		return 0, io.EOF
	}
	return c.input.Read(p)
}
func (c *memoryConn) Write(p []byte) (int, error)    { return c.output.Write(p) }
func (*memoryConn) Close() error                     { return nil }
func (*memoryConn) LocalAddr() net.Addr              { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8000} }
func (*memoryConn) RemoteAddr() net.Addr             { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1000} }
func (*memoryConn) SetDeadline(time.Time) error      { return nil }
func (*memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (*memoryConn) SetWriteDeadline(time.Time) error { return nil }

type recordingHandler struct{ accepted int }

func (h *recordingHandler) NewConnectionEx(_ context.Context, c net.Conn, _, _ M.Socksaddr, close N.CloseHandlerFunc) {
	h.accepted++
	c.Close()
	if close != nil {
		close(nil)
	}
}
func (*recordingHandler) NewPacketConnectionEx(context.Context, N.PacketConn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc) {
}
func clientWire(t *testing.T, psk []byte) []byte {
	t.Helper()
	client, err := snellv6.NewClient(snellv6.ClientOptions{PSK: psk, Mode: snellv6.ModeDefault})
	if err != nil {
		t.Fatal(err)
	}
	raw := new(memoryConn)
	if _, err = client.DialConn(raw, M.ParseSocksaddr("127.0.0.1:80")); err != nil {
		t.Fatal(err)
	}
	return bytes.Clone(raw.output.Bytes())
}
func TestLongCachedUserSurvivesNATBackoff(t *testing.T) {
	h := new(recordingHandler)
	r := protocol.ResolvedListenerSpec{Spec: model.ListenerSpec{CredentialRefs: []string{"alice", "bob"}}, Credentials: map[string][]byte{"alice": []byte("alice-long-snells-secret"), "bob": []byte("bob-long-snells-secret")}}
	s, err := newServer(r, h, Options{Version: 6, Mode: "default"})
	if err != nil {
		t.Fatal(err)
	}
	if s.users[0].probe.HeaderLen() == s.users[1].probe.HeaderLen() {
		t.Fatal("fixture requires differing header lengths")
	}
	t.Logf("short header=%d, long header=%d", s.users[0].probe.HeaderLen(), s.users[1].probe.HeaderLen())
	now := time.Now()
	s.selector = authscan.NewSelector(authscan.HashAddr, authscan.GuardOptions{TimeFunc: func() time.Time { return now }})
	serve := func(p []byte) error {
		return s.serve(context.Background(), &memoryConn{input: bytes.NewReader(p)}, M.ParseSocksaddr("127.0.0.1:1000"), nil)
	}
	_ = serve(clientWire(t, s.users[1].psk))
	if h.accepted != 1 {
		t.Fatal("initial authentication did not complete")
	}
	if err = serve(bytes.Repeat([]byte{0xa5}, 320)); !errors.Is(err, authscan.ErrNoMatch) {
		t.Fatal("bad handshake did not reject", err)
	}
	err = serve(clientWire(t, s.users[1].psk))
	if h.accepted != 2 {
		t.Fatalf("previously authenticated cached long-header user rejected during another user's source backoff: %v", err)
	}
}

func TestBackoffDoesNotReadLongCachedHeaderForShortUser(t *testing.T) {
	h := new(recordingHandler)
	r := protocol.ResolvedListenerSpec{Spec: model.ListenerSpec{CredentialRefs: []string{"alice", "bob"}}, Credentials: map[string][]byte{"alice": []byte("alice-long-snells-secret"), "bob": []byte("bob-long-snells-secret")}}
	s, err := newServer(r, h, Options{Version: 6, Mode: "default"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s.selector = authscan.NewSelector(authscan.HashAddr, authscan.GuardOptions{TimeFunc: func() time.Time { return now }})
	serve := func(p []byte) error {
		return s.serve(context.Background(), &memoryConn{input: bytes.NewReader(p)}, M.ParseSocksaddr("127.0.0.1:1000"), nil)
	}
	_ = serve(clientWire(t, s.users[1].psk))
	if h.accepted != 1 {
		t.Fatal("cache warmup failed")
	}
	_ = serve(bytes.Repeat([]byte{0xa5}, 320))
	// Only the short user's header is available. Reading the long cached user's
	// length first would return EOF here (or block on a real network connection).
	short := clientWire(t, s.users[0].psk)[:s.users[0].probe.HeaderLen()]
	if err = serve(short); !errors.Is(err, authscan.ErrLimited) {
		t.Fatal("read past an uncached shorter handshake during source backoff", err)
	}
	if h.accepted != 1 {
		t.Fatal("uncached user bypassed source backoff")
	}
}
