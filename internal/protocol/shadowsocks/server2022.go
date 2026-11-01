// SPDX-License-Identifier: GPL-3.0-only
package shadowsocks

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/Ember-Moth/Lunaris/internal/transport"
	SS "github.com/sagernet/sing-shadowsocks"
	upstream "github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/crypto/chacha20poly1305"
	"lukechampine.com/blake3"
)

type server2022 struct {
	owner         *Server
	service       SS.Service
	newUDPService func(SS.Handler, string) (SS.Service, error)
	route         func([]byte) (udp2022Key, uint64, error)
	minimum       int
	packetMu      sync.Mutex
	ctx           context.Context
	socket        net.PacketConn
	stopped       bool
	states        map[udp2022Key]*udp2022State
	active        atomic.Int64
	cleaned       time.Time
	wg            sync.WaitGroup
	once          sync.Once
	done          chan struct{}
}
type udp2022Key struct {
	session uint64
	user    string
}
type udp2022State struct {
	service   SS.Service
	window    upstream.SlidingWindow
	last      time.Time
	active    bool
	published chan struct{}
	queue     *packetSession
	mu        sync.Mutex
	reserved  bool
	cancel    context.CancelFunc
	flowDone  chan struct{}
}
type wire2022Key struct{}

func (f Factory) build2022(r protocol.ResolvedListenerSpec, d protocol.Dependencies, o Options) (transport.Binding, error) {
	if fields := f.Validate(r.Spec); len(fields) > 0 {
		return transport.Binding{}, errors.New(fields[0].Message)
	}
	if err := f.ValidateAssets(r); err != nil {
		return transport.Binding{}, err
	}
	if d.Handler == nil {
		return transport.Binding{}, errors.New("Shadowsocks relay handler required")
	}
	s := &server2022{owner: newServer(r.Limits, d.Handler, nil), states: make(map[udp2022Key]*udp2022State), done: make(chan struct{}), minimum: 32 + 27}
	if o.Method == "2022-blake3-aes-128-gcm" {
		s.minimum = 16 + 27
	}
	masterRef := r.Spec.CredentialRefs[0]
	if o.ServerKeyRef != "" {
		masterRef = o.ServerKeyRef
		s.minimum += 16
	}
	master := string(r.Credentials[masterRef])
	users := make(map[string]string)
	for _, ref := range r.Spec.CredentialRefs {
		users[ref] = string(r.Credentials[ref])
	}
	s.newUDPService = func(handler SS.Handler, user string) (SS.Service, error) {
		// Each native UDP association has its own upstream NAT instance. Its lifetime
		// is controlled here; upstream age eviction must not race with a replacement.
		if o.ServerKeyRef == "" {
			return upstream.NewServiceWithPassword(o.Method, master, math.MaxInt32, handler, nil)
		}
		multi, err := upstream.NewMultiServiceWithPassword[string](o.Method, master, math.MaxInt32, handler, nil)
		if err != nil {
			return nil, err
		}
		var refs, passwords []string
		for ref, password := range users {
			if user == "" || user == ref {
				refs = append(refs, ref)
				passwords = append(passwords, password)
			}
		}
		if err = multi.UpdateUsersWithPasswords(refs, passwords); err != nil {
			return nil, err
		}
		return multi, nil
	}
	var err error
	s.service, err = s.newUDPService(s, "")
	if err != nil {
		return transport.Binding{}, errors.New("invalid Shadowsocks 2022 key configuration")
	}
	s.route, err = udp2022Router(o.Method, master, users, o.ServerKeyRef != "")
	if err != nil {
		return transport.Binding{}, err
	}
	return transport.Binding{Stream: &transport.StreamHandler{Serve: s.serveStream}, Packet: &transport.PacketHandler{Serve: s.servePacket, Close: s.closePacket}}, nil
}
func (s *server2022) serveStream(ctx context.Context, c net.Conn, src M.Socksaddr, close N.CloseHandlerFunc) error {
	ctx = context.WithValue(ctx, wire2022Key{}, c)
	err := s.service.NewConnection(ctx, &transport.FirstRead{Conn: c, Minimum: s.minimum}, M.Metadata{Source: src})
	if close != nil {
		close(err)
	}
	return err
}
func (s *server2022) NewConnection(ctx context.Context, c net.Conn, m M.Metadata) error {
	wire := ctx.Value(wire2022Key{}).(net.Conn)
	safe := &joined2022Conn{Conn: c, wire: wire}
	done := make(chan error, 1)
	s.owner.handler.NewConnectionEx(ctx, safe, m.Source, m.Destination, N.OnceClose(func(err error) { done <- err }))
	return <-done
}
func (s *server2022) NewPacketConnection(context.Context, N.PacketConn, M.Metadata) error {
	return errors.New("native UDP requires an owned association")
}
func (s *server2022) NewError(context.Context, error) {}

// The upstream first-response writer is lazy. Revoke the wire before joining
// reads/writes and closing its codecs, so Close cannot race with initialization.
// Do not expose Upstream: sing must not bypass this lifetime boundary.
type joined2022Conn struct {
	net.Conn
	wire            net.Conn
	readMu, writeMu sync.Mutex
	once            sync.Once
	closed          atomic.Bool
}

func (c *joined2022Conn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	return c.Conn.Read(p)
}
func (c *joined2022Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	return c.Conn.Write(p)
}
func (c *joined2022Conn) Close() error {
	var err error
	c.once.Do(func() {
		c.closed.Store(true)
		_ = c.wire.Close()
		c.readMu.Lock()
		defer c.readMu.Unlock()
		c.writeMu.Lock()
		defer c.writeMu.Unlock()
		err = c.Conn.Close()
	})
	return err
}

// This reads only the routing identity. The upstream service still authenticates
// and decodes every accepted packet, checks timestamps, and encodes responses.
// Unauthenticated identities never enter the association/replay maps.
func udp2022Router(method, master string, users map[string]string, multi bool) (func([]byte) (udp2022Key, uint64, error), error) {
	key, _ := base64.StdEncoding.DecodeString(master)
	var block cipher.Block
	var aead cipher.AEAD
	var err error
	if method == "2022-blake3-chacha20-poly1305" {
		aead, err = chacha20poly1305.NewX(key)
	} else {
		block, err = aes.NewCipher(key)
	}
	if err != nil {
		return nil, err
	}
	identities := map[[16]byte]string{}
	if multi {
		for user, password := range users {
			key, _ := base64.StdEncoding.DecodeString(password)
			sum := blake3.Sum512(key)
			var id [16]byte
			copy(id[:], sum[:16])
			identities[id] = user
		}
	}
	return func(packet []byte) (udp2022Key, uint64, error) {
		var header [16]byte
		var user string
		if aead != nil {
			if len(packet) < 24+16+aead.Overhead() {
				return udp2022Key{}, 0, upstream.ErrPacketTooShort
			}
			plain, err := aead.Open(nil, packet[:24], packet[24:], nil)
			if err != nil {
				return udp2022Key{}, 0, err
			}
			copy(header[:], plain)
		} else {
			size := 16
			if multi {
				size = 32
			}
			if len(packet) < size {
				return udp2022Key{}, 0, upstream.ErrPacketTooShort
			}
			block.Decrypt(header[:], packet[:16])
			if multi {
				var id [16]byte
				block.Decrypt(id[:], packet[16:32])
				for i := range id {
					id[i] ^= header[i]
				}
				var ok bool
				user, ok = identities[id]
				if !ok {
					return udp2022Key{}, 0, upstream.ErrInvalidRequest
				}
			}
		}
		return udp2022Key{session: binary.BigEndian.Uint64(header[:8]), user: user}, binary.BigEndian.Uint64(header[8:]), nil
	}, nil
}
func (s *server2022) servePacket(ctx context.Context, socket net.PacketConn) error {
	s.packetMu.Lock()
	if s.stopped {
		s.packetMu.Unlock()
		return net.ErrClosed
	}
	s.ctx = ctx
	s.socket = socket
	s.packetMu.Unlock()
	wire := &packet2022Writer{s: s}
	for {
		buffer := buf.NewSize(65535)
		n, addr, err := socket.ReadFrom(buffer.FreeBytes())
		if err != nil {
			buffer.Release()
			return err
		}
		buffer.Truncate(n)
		key, id, err := s.route(buffer.Bytes())
		if err != nil {
			buffer.Release()
			continue
		}
		s.packetMu.Lock()
		if s.stopped {
			s.packetMu.Unlock()
			buffer.Release()
			return net.ErrClosed
		}
		now := time.Now()
		if now.Sub(s.cleaned) > time.Second {
			for k, state := range s.states {
				if !state.active && now.Sub(state.last) > time.Minute {
					delete(s.states, k)
				}
			}
			s.cleaned = now
		}
		state := s.states[key]
		if state != nil && !state.window.Check(id) {
			s.packetMu.Unlock()
			buffer.Release()
			continue
		}
		fresh := state == nil || !state.active
		previous := state
		if fresh {
			if (state == nil && len(s.states) >= min(65536, max(1024, 4*s.owner.limits.MaxUDPSessions))) || !s.reserveUDP() {
				s.packetMu.Unlock()
				buffer.Release()
				continue
			}
			state = &udp2022State{active: true, published: make(chan struct{}), reserved: true}
			if previous != nil {
				state.window = previous.window
			}
			state.service, err = s.newUDPService(&udp2022Handler{s: s, key: key, state: state}, key.user)
			if err != nil {
				s.active.Add(-1)
				s.packetMu.Unlock()
				buffer.Release()
				continue
			}
			s.states[key] = state
			s.wg.Add(1)
		}
		err = state.service.NewPacket(context.WithoutCancel(ctx), wire, buffer, M.Metadata{Source: M.SocksaddrFromNet(addr).Unwrap()})
		if err == nil {
			state.window.Add(id)
			state.last = now
		} else if fresh {
			if previous == nil {
				delete(s.states, key)
			} else {
				s.states[key] = previous
			}
			s.active.Add(-1)
			s.wg.Done()
		}
		if fresh {
			close(state.published)
		}
		s.packetMu.Unlock()
		if err != nil {
			buffer.Release()
		}
	}
}

type udp2022Handler struct {
	s     *server2022
	key   udp2022Key
	state *udp2022State
}

func (*udp2022Handler) NewConnection(context.Context, net.Conn, M.Metadata) error {
	return errors.New("UDP association is not a TCP service")
}
func (*udp2022Handler) NewError(context.Context, error) {}
func (s *server2022) reserveUDP() bool {
	for {
		current := s.active.Load()
		if current >= int64(s.owner.limits.MaxUDPSessions) {
			return false
		}
		if s.active.CompareAndSwap(current, current+1) {
			return true
		}
	}
}
func (h *udp2022Handler) NewPacketConnection(ctx context.Context, c N.PacketConn, m M.Metadata) error {
	<-h.state.published
	s, state := h.s, h.state
	defer s.wg.Done()
	s.packetMu.Lock()
	root := s.ctx
	stopped := s.stopped
	s.packetMu.Unlock()
	stopRoot := context.AfterFunc(root, func() { _ = c.SetReadDeadline(time.Now()) })
	defer stopRoot()
	readPacket := func() (*buf.Buffer, M.Socksaddr, error) {
		b := buf.NewSize(65535)
		dst, err := c.ReadPacket(b)
		if err != nil {
			b.Release()
			return nil, dst, err
		}
		return b, dst, nil
	}
	if waiter, ok := c.(N.PacketReadWaiter); ok {
		waiter.InitializeReadWaiter(N.ReadWaitOptions{})
		readPacket = waiter.WaitReadPacket
	}
	lifetime := max(time.Minute, s.owner.limits.UDPIdleTimeout)
	for !stopped && root.Err() == nil {
		_ = c.SetReadDeadline(time.Now().Add(lifetime))
		if root.Err() != nil {
			break
		}
		b, dst, err := readPacket()
		if err != nil {
			break
		}
		small := buf.NewSize(b.Len())
		_, _ = small.Write(b.Bytes())
		b.Release()
		state.mu.Lock()
		q := state.queue
		fresh := q == nil
		if fresh {
			if !state.reserved && !s.reserveUDP() {
				state.mu.Unlock()
				small.Release()
				continue
			}
			state.reserved = true
			q = newPacketSession(s.owner, m.Source.AddrPort())
			q.writer = c
			state.queue = q
			state.flowDone = make(chan struct{})
		}
		q.offer(small, dst)
		var startFlow func()
		if fresh {
			relayCtx, cancel := context.WithCancel(ctx)
			state.cancel = cancel
			stop := context.AfterFunc(root, cancel)
			done := state.flowDone
			// The upstream association and crypto session survive an idle relay. This
			// preserves its server session ID when the same client resumes within a minute.
			startFlow = func() {
				s.owner.handler.NewPacketConnectionEx(relayCtx, q, m.Source, dst, N.OnceClose(func(error) {
					state.mu.Lock()
					q.Close()
					state.queue = nil
					state.cancel = nil
					state.reserved = false
					s.active.Add(-1)
					state.mu.Unlock()
					stop()
					cancel()
					close(done)
				}))
			}
		}
		state.mu.Unlock()
		if startFlow != nil {
			startFlow()
		}
	}
	// Keep draining while waiting for serialized delivery to finish. Its legacy
	// NAT queue is blocking, so closing the reader before this point can deadlock.
	_ = c.SetReadDeadline(time.Time{})
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for {
			b, _, err := readPacket()
			if err != nil {
				return
			}
			b.Release()
		}
	}()
	s.packetMu.Lock()
	state.active = false
	state.service = nil
	c.Close()
	s.packetMu.Unlock()
	<-drained
	state.mu.Lock()
	done := state.flowDone
	if state.cancel != nil {
		state.cancel()
	}
	if state.queue != nil {
		state.queue.Close()
	} else if state.reserved {
		state.reserved = false
		s.active.Add(-1)
	}
	state.mu.Unlock()
	if done != nil {
		<-done
	}
	return nil
}
func (s *server2022) closePacket(ctx context.Context) error {
	s.once.Do(func() {
		go func() {
			s.packetMu.Lock()
			s.stopped = true
			for _, state := range s.states {
				state.mu.Lock()
				if state.cancel != nil {
					state.cancel()
				}
				if state.queue != nil {
					state.queue.Close()
				}
				state.mu.Unlock()
			}
			s.packetMu.Unlock()
			s.wg.Wait()
			close(s.done)
		}()
	})
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type packet2022Writer struct{ s *server2022 }

func (c *packet2022Writer) WritePacket(b *buf.Buffer, dst M.Socksaddr) error {
	defer b.Release()
	c.s.owner.writeMu.Lock()
	defer c.s.owner.writeMu.Unlock()
	if err := c.s.socket.SetWriteDeadline(time.Now().Add(c.s.owner.limits.DialTimeout)); err != nil {
		return err
	}
	_, err := c.s.socket.WriteTo(b.Bytes(), dst.UDPAddr())
	return err
}
func (*packet2022Writer) ReadPacket(*buf.Buffer) (M.Socksaddr, error) {
	return M.Socksaddr{}, errors.New("write-only packet sink")
}
func (*packet2022Writer) Close() error                     { return nil }
func (c *packet2022Writer) LocalAddr() net.Addr            { return c.s.socket.LocalAddr() }
func (*packet2022Writer) SetDeadline(time.Time) error      { return nil }
func (*packet2022Writer) SetReadDeadline(time.Time) error  { return nil }
func (*packet2022Writer) SetWriteDeadline(time.Time) error { return nil }
