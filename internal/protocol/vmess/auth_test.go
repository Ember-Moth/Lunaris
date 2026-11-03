// SPDX-License-Identifier: GPL-3.0-only
package vmess

import (
	"bytes"
	"context"
	"crypto/cipher"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/authscan"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	upstream "github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type memoryConn struct {
	bytes.Buffer
	input *bytes.Reader
}

func (c *memoryConn) Read(p []byte) (int, error)     { return c.input.Read(p) }
func (*memoryConn) Close() error                     { return nil }
func (*memoryConn) LocalAddr() net.Addr              { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2000} }
func (*memoryConn) RemoteAddr() net.Addr             { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1000} }
func (*memoryConn) SetDeadline(time.Time) error      { return nil }
func (*memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (*memoryConn) SetWriteDeadline(time.Time) error { return nil }

type recordingHandler struct{ users []string }

func (h *recordingHandler) NewConnectionEx(ctx context.Context, c net.Conn, _, _ M.Socksaddr, close N.CloseHandlerFunc) {
	u, _ := auth.UserFromContext[string](ctx)
	h.users = append(h.users, u)
	if close != nil {
		close(nil)
	}
}
func (*recordingHandler) NewPacketConnectionEx(context.Context, N.PacketConn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc) {
}

type countedBlock struct {
	cipher.Block
	count *int
}

func (b countedBlock) Decrypt(dst, src []byte) { *b.count++; b.Block.Decrypt(dst, src) }
func vmessWire(t *testing.T, id string) []byte {
	t.Helper()
	c := new(memoryConn)
	client, err := upstream.NewClient(id, "aes-128-gcm", 0)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := client.DialConn(c, M.ParseSocksaddr("127.0.0.1:80"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	return bytes.Clone(c.Bytes())
}
func TestVMessCacheOnlyAfterFullAuthenticationAndReplay(t *testing.T) {
	first, second := "7d27b49e-3b7b-45dc-8308-f0c15c152bde", "c3792d13-4443-48ee-b82a-f8147a7eb7d1"
	r := protocol.ResolvedListenerSpec{Spec: model.ListenerSpec{CredentialRefs: []string{"first", "second"}}, Credentials: map[string][]byte{"first": []byte(first), "second": []byte(second)}}
	h := new(recordingHandler)
	s, err := newServer(r, h)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s.selector = authscan.NewSelector(authscan.HashAddr, authscan.GuardOptions{TimeFunc: func() time.Time { return now }})
	count := 0
	for i := range s.users {
		s.users[i].block = countedBlock{s.users[i].block, &count}
	}
	serve := func(wire []byte) error {
		return s.serve(context.Background(), &memoryConn{input: bytes.NewReader(wire)}, M.ParseSocksaddr("127.0.0.1:1000"), nil)
	}
	if err = serve(vmessWire(t, second)[:16]); err == nil {
		t.Fatal("truncated auth accepted")
	}
	count = 0
	bad := vmessWire(t, second)
	bad[16] ^= 1
	if err = serve(bad); err == nil {
		t.Fatal("corrupt header accepted")
	}
	if count != 2 || len(h.users) != 0 {
		t.Fatal("partial auth cached", count, h.users)
	}
	now = now.Add(time.Second)
	count = 0
	valid := vmessWire(t, second)
	if err = serve(valid); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatal("incomplete request cached", count)
	}
	count = 0
	if err = serve(vmessWire(t, second)); err != nil || count != 1 {
		t.Fatal("warm auth", count, err)
	}
	if err = serve(valid); err == nil {
		t.Fatal("replay accepted")
	}
	if err = serve(vmessWire(t, first)); !errors.Is(err, authscan.ErrLimited) {
		t.Fatal("replay reset backoff", err)
	}
	count = 0
	if err = serve(vmessWire(t, second)); err != nil || count != 1 {
		t.Fatal("known NAT user blocked", count, err)
	}
	if len(h.users) != 3 {
		t.Fatal("unexpected authenticated requests", h.users)
	}
}
