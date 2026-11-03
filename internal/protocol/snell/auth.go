// SPDX-License-Identifier: GPL-3.0-only
package snell

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sort"

	"github.com/Ember-Moth/Lunaris/internal/authscan"
	"github.com/Ember-Moth/Lunaris/internal/ingress"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/Ember-Moth/Lunaris/internal/protocol/snell/native5"
	"github.com/Ember-Moth/Lunaris/internal/protocol/snell/probe"
	upstream "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv6"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type credential struct {
	ref     string
	psk     []byte
	probe   *probe.Probe
	service upstream.Service
}
type server struct {
	users    []credential
	selector *authscan.Selector[netip.Addr]
	replay   *native5.SaltReplayCache
	handler  streamBoundary
	obfs     upstream.ObfsConfig
	version  int
}
type matchKey struct{}

func newServer(r protocol.ResolvedListenerSpec, handler protocol.RelayHandler, options Options) (*server, error) {
	// Polaris's Argon2 work estimate: 20k derivations/core/s with a quarter
	// core budget. Both cached and cold attempts consume this same allowance.
	rate := max(runtime.GOMAXPROCS(0), 1) * 5000
	s := &server{selector: authscan.NewSelector(authscan.HashAddr, authscan.GuardOptions{WorkRate: rate}), replay: new(native5.SaltReplayCache), handler: streamBoundary{next: handler}, version: options.Version}
	s.obfs.Mode, _ = upstream.ParseObfsMode(options.Obfs)
	for _, ref := range r.Spec.CredentialRefs {
		user := credential{ref: ref, psk: bytes.Clone(r.Credentials[ref])}
		var err error
		if options.Version == 5 {
			user.service, err = native5.NewService(native5.ServiceOptions{PSK: user.psk, Handler: s, ReplayCache: s.replay})
		} else {
			mode, _ := snellv6.ParseMode(options.Mode)
			user.service, err = snellv6.NewService(snellv6.ServerOptions{PSK: user.psk, Mode: mode, Handler: s})
			if mode == snellv6.ModeDefault {
				user.probe = probe.New(user.psk)
			}
		}
		if err != nil {
			return nil, err
		}
		s.users = append(s.users, user)
	}
	if s.users[0].probe != nil {
		sort.SliceStable(s.users, func(i, j int) bool { return s.users[i].probe.HeaderLen() < s.users[j].probe.HeaderLen() })
	}
	return s, nil
}

func (s *server) serve(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) error {
	peer := ingress.PeerIP(ctx, conn.RemoteAddr())
	if s.version == 5 {
		conn = s.obfs.ServerConn(conn)
	}
	header := make([]byte, 0, 320)
	ensure := func(n int) error {
		if len(header) >= n {
			return nil
		}
		previous := len(header)
		header = header[:n]
		_, err := io.ReadFull(conn, header[previous:])
		return err
	}
	var salt [16]byte
	try := func(index int) bool {
		user := &s.users[index]
		var prefix, sealed []byte
		if user.probe != nil {
			salt, prefix, sealed = user.probe.Header(header)
		} else {
			copy(salt[:], header[:16])
			sealed = header[16:]
		}
		aead, err := upstream.NewAEAD(upstream.DeriveKey(user.psk, salt[:]))
		if err != nil {
			return false
		}
		var nonce [12]byte
		var plain [upstream.HeaderCipherLen]byte
		_, err = aead.Open(plain[:0], nonce[:], sealed, prefix)
		return err == nil
	}
	var match *authscan.Match[netip.Addr]
	var err error
	if s.users[0].probe == nil {
		if err = ensure(16 + upstream.HeaderCipherLen); err != nil {
			return err
		}
		match, err = s.selector.Find(peer, len(s.users), try)
	} else {
		minimum := s.users[0].probe.HeaderLen()
		if err = ensure(minimum); err != nil {
			return err
		}
		match, err = s.selector.FindPrepared(peer, len(s.users), func(index int, cached bool) (bool, error) {
			p := s.users[index].probe
			if cached && len(header) < p.HeaderLen() {
				return false, nil
			}
			if err := ensure(p.SaltBlockLen()); err != nil {
				return false, err
			}
			if !p.Matches(header) {
				return false, nil
			}
			return true, ensure(p.HeaderLen())
		}, try)
	}
	if err != nil {
		return err
	}
	user := &s.users[match.Index]
	if s.version == 6 {
		// v6 upstream has no salt replay filter. A verified encrypted header is
		// enough to reserve its salt; full request validation still gates caching.
		key := sha256.Sum256(append(append([]byte(nil), user.psk...), salt[:]...))
		if s.replay.CheckAndAdd(key[:]) {
			match.Reject()
			return upstream.ErrBadUserKey
		}
	}
	ctx = auth.ContextWithUser(context.WithValue(ctx, matchKey{}, match), user.ref)
	err = user.service.NewConnection(ctx, authscan.ReplayPrefix(conn, header), source, onClose)
	if authscan.Rejected(err) {
		match.Reject()
	}
	return err
}
func (s *server) NewConnectionEx(ctx context.Context, c net.Conn, src, dst M.Socksaddr, close N.CloseHandlerFunc) {
	ctx.Value(matchKey{}).(*authscan.Match[netip.Addr]).Accept()
	s.handler.NewConnectionEx(ctx, c, src, dst, close)
}
func (s *server) NewPacketConnectionEx(ctx context.Context, c N.PacketConn, src, dst M.Socksaddr, close N.CloseHandlerFunc) {
	ctx.Value(matchKey{}).(*authscan.Match[netip.Addr]).Accept()
	s.handler.NewPacketConnectionEx(ctx, c, src, dst, close)
}
