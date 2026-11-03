// SPDX-License-Identifier: GPL-3.0-only
package native

import (
	"bytes"
	"context"
	"errors"
	"github.com/Ember-Moth/Lunaris/internal/authscan"
	"github.com/Ember-Moth/Lunaris/internal/ingress"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type fixtureHandler struct{}

func (fixtureHandler) NewConnectionEx(context.Context, net.Conn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc) {
}
func (fixtureHandler) NewPacketConnectionEx(context.Context, N.PacketConn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc) {
}

type fixtureDatagram struct {
	data []byte
	src  net.Addr
}
type fixturePacketConn struct {
	input chan fixtureDatagram
	done  chan struct{}
	once  sync.Once
}

func (c *fixturePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case d := <-c.input:
		return copy(p, d.data), d.src, nil
	case <-c.done:
		return 0, nil, net.ErrClosed
	}
}
func (*fixturePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (c *fixturePacketConn) Close() error                            { c.once.Do(func() { close(c.done) }); return nil }
func (*fixturePacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8000}
}
func (*fixturePacketConn) SetDeadline(time.Time) error      { return nil }
func (*fixturePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*fixturePacketConn) SetWriteDeadline(time.Time) error { return nil }
func fixturePacketServer(t *testing.T) (*Server, *fixturePacketConn) {
	t.Helper()
	s, err := NewServer(ServerOptions{Context: context.Background(), ListenAddress: "fixture", Transport: TransportUDP, TCPHandler: fixtureHandler{}, Users: []User{{Name: "alice", Password: "alice-pass"}, {Name: "bob", Password: "bob-pass"}}})
	if err != nil {
		t.Fatal(err)
	}
	p := &fixturePacketConn{input: make(chan fixtureDatagram, 8), done: make(chan struct{})}
	s.packet = p
	s.wg.Add(1)
	go s.listenPacket()
	t.Cleanup(func() { s.Close() })
	return s, p
}
func fixtureOpen(t *testing.T, s *Server, user, index int) []byte {
	t.Helper()
	u := s.users.Load().users[user]
	keys, _ := u.keysAt(time.Now())
	p, err := sealPacket(nil, metadata{protocol: openSessionRequest, sessionID: uint32(index)}, nil, keys.aead[1], u.name)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func fixtureAccepted(t *testing.T, s *Server) net.Conn {
	t.Helper()
	select {
	case c := <-s.accepted:
		return c
	case <-time.After(time.Second):
		t.Fatal("no accepted session")
		return nil
	}
}
func TestMieruReplayFromDifferentPort(t *testing.T) {
	s, p := fixturePacketServer(t)
	wire := fixtureOpen(t, s, 0, 7)
	p.input <- fixtureDatagram{wire, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1001}}
	first := fixtureAccepted(t, s)
	_ = first
	p.input <- fixtureDatagram{bytes.Clone(wire), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1002}}
	p.input <- fixtureDatagram{fixtureOpen(t, s, 1, 8), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 1003}}
	next := fixtureAccepted(t, s)
	if next.(interface{ UserName() string }).UserName() != "bob" {
		t.Fatal("replayed ciphertext opened another Alice session")
	}

}
func TestMieruSameSourceSessionIDIsolation(t *testing.T) {
	s, p := fixturePacketServer(t)
	source := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1001}
	firstWire := fixtureOpen(t, s, 0, 7)
	p.input <- fixtureDatagram{firstWire, source}
	alice := fixtureAccepted(t, s).(*packetSession)
	p.input <- fixtureDatagram{fixtureOpen(t, s, 1, 7), source}
	bob := fixtureAccepted(t, s).(*packetSession)
	if bob.UserName() != "bob" {
		t.Fatal("wrong user")
	}
	send := func(user int, seq uint32, payload string) {
		u := s.users.Load().users[user]
		keys, _ := u.keysAt(time.Now())
		wire, err := sealPacket(nil, metadata{protocol: dataClientToServer, sessionID: 7, seq: seq, windowSize: 32}, []byte(payload), keys.aead[1], u.name)
		if err != nil {
			t.Fatal(err)
		}
		p.input <- fixtureDatagram{wire, source}
	}
	read := func(conn net.Conn, want string) {
		conn.SetReadDeadline(time.Now().Add(time.Second))
		got := make([]byte, len(want))
		if _, err := io.ReadFull(conn, got); err != nil || string(got) != want {
			t.Fatal("user payload isolation", string(got), err)
		}
	}
	// Retransmitting the original opener must keep its existing session.
	p.input <- fixtureDatagram{bytes.Clone(firstWire), source}
	send(0, 1, "alice-data")
	send(1, 1, "bob-data")
	read(alice, "alice-data")
	read(bob, "bob-data")
	alice.Close()
	// Closing Alice must not delete Bob's equal-ID session or cached epoch key.
	send(1, 2, "bob-still-open")
	read(bob, "bob-still-open")
	p.input <- fixtureDatagram{fixtureOpen(t, s, 0, 7), source}
	replacement := fixtureAccepted(t, s)
	if replacement.(interface{ UserName() string }).UserName() != "alice" {
		t.Fatal("wrong replacement user")
	}
	bob.Close()
	replacement.Close()
	s.remoteCipherMu.Lock()
	remaining := len(s.remoteCiphers)
	s.remoteCipherMu.Unlock()
	if remaining != 0 {
		t.Fatalf("credential key cache leaked %d endpoints", remaining)
	}
}

type fixtureStreamConn struct{ input *bytes.Reader }

func (c *fixtureStreamConn) Read(p []byte) (int, error) { return c.input.Read(p) }
func (*fixtureStreamConn) Write(p []byte) (int, error)  { return len(p), nil }
func (*fixtureStreamConn) Close() error                 { return nil }
func (*fixtureStreamConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8000}
}
func (*fixtureStreamConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1000}
}
func (*fixtureStreamConn) SetDeadline(time.Time) error      { return nil }
func (*fixtureStreamConn) SetReadDeadline(time.Time) error  { return nil }
func (*fixtureStreamConn) SetWriteDeadline(time.Time) error { return nil }
func TestMieruReplayKeysAreCredentialSeparated(t *testing.T) {
	s, p := fixturePacketServer(t)
	_ = p
	nonce := bytes.Repeat([]byte{0x7e}, nonceSize)
	for _, user := range s.users.Load().users {
		keys, _ := user.keysAt(time.Now())
		meta := metadata{protocol: openSessionRequest, sessionID: 7}
		encrypted := keys.aead[1].Seal(bytes.Clone(nonce), nonce, meta.marshal(nil, time.Now()), nil)
		underlay := &streamUnderlay{server: s, ctx: context.Background(), conn: &fixtureStreamConn{input: bytes.NewReader(encrypted)}, handshakeDeadline: time.Now().Add(time.Second)}
		if _, err := underlay.readSegment(); err != nil {
			t.Fatalf("user %s rejected solely because another credential used the same nonce: %v", user.name, err)
		}
	}
}

type fixtureCaptureConn struct {
	fixtureStreamConn
	output bytes.Buffer
}

func (c *fixtureCaptureConn) Write(p []byte) (int, error) { return c.output.Write(p) }
func TestMieruReflectedReplyDoesNotCommitCandidate(t *testing.T) {
	s, _ := fixturePacketServer(t)
	user := s.users.Load().users[1]
	keys, _ := user.keysAt(time.Now())
	now := time.Now()
	s.users.Load().scan = authscan.NewSelector(authscan.HashAddr, authscan.GuardOptions{TimeFunc: func() time.Time { return now }})
	notifications := 0
	s.option.OnAuthenticated = func(context.Context) { notifications++ }
	capture := new(fixtureCaptureConn)
	outgoing := &streamUnderlay{server: s, user: user, conn: capture, send: streamCipher{aead: keys.aead[1]}}
	if err := outgoing.writeSegment(metadata{protocol: openSessionResponse, sessionID: 7}, nil); err != nil {
		t.Fatal(err)
	}
	reflected := &streamUnderlay{server: s, ctx: context.Background(), conn: &fixtureStreamConn{input: bytes.NewReader(capture.output.Bytes())}, handshakeDeadline: time.Now().Add(time.Second)}
	if _, err := reflected.readSegment(); err == nil {
		t.Fatal("server reply accepted as a client handshake")
	}
	if reflected.authenticated.Load() || notifications != 0 {
		t.Fatal("invalid handshake released authentication admission")
	}
	_, err := s.users.Load().scan.Find(ingress.AddressIP(reflected.conn.RemoteAddr()), 2, func(int) bool { t.Fatal("invalid reply warmed cache or reset failure backoff"); return true })
	if !errors.Is(err, authscan.ErrLimited) {
		t.Fatal("missing failure backoff", err)
	}
}
