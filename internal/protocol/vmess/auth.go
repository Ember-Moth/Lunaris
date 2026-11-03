// SPDX-License-Identifier: GPL-3.0-only
package vmess

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/authscan"
	"github.com/Ember-Moth/Lunaris/internal/ingress"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/gofrs/uuid/v5"
	upstream "github.com/sagernet/sing-vmess"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type userService struct {
	block   cipher.Block
	service *upstream.Service[string]
}

// The timestamp check accepts +/-120 whole seconds. Retain each AuthID for
// 241 seconds from arrival, covering even a maximally future-dated valid ID.
const replayLifetime = 241 * time.Second

var errAuthReplay = errors.New("replayed or capacity-limited VMess authentication")

type replayKey struct {
	user int
	id   [16]byte
}
type server struct {
	now      func() time.Time
	replay   *authscan.ReplayWindow[replayKey]
	users    []userService
	selector *authscan.Selector[netip.Addr]
	handler  protocol.RelayHandler
}
type matchKey struct{}

func newServer(r protocol.ResolvedListenerSpec, handler protocol.RelayHandler) (*server, error) {
	s := &server{selector: authscan.NewSelector(authscan.HashAddr, authscan.GuardOptions{WorkRate: 1 << 22}), handler: handler, now: time.Now, replay: authscan.NewReplayWindow[replayKey](65536, replayLifetime, nil)}
	for _, ref := range r.Spec.CredentialRefs {
		id, err := uuid.FromString(string(r.Credentials[ref]))
		if err != nil {
			return nil, err
		}
		key := upstream.Key(id)
		block, err := aes.NewCipher(upstream.KDF(key[:], upstream.KDFSaltConstAuthIDEncryptionKey)[:16])
		if err != nil {
			return nil, err
		}
		service := upstream.NewService[string](s, upstream.ServiceWithDisableHeaderProtection())
		if err := service.UpdateUsers([]string{ref}, []string{id.String()}, []int{0}); err != nil {
			return nil, err
		}
		s.users = append(s.users, userService{block, service})
	}
	return s, nil
}

func (s *server) serve(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) error {
	var header [16]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return err
	}
	now := s.now().Unix()
	match, err := s.selector.Find(ingress.PeerIP(ctx, conn.RemoteAddr()), len(s.users), func(index int) bool {
		var decoded [16]byte
		s.users[index].block.Decrypt(decoded[:], header[:])
		timestamp := int64(binary.BigEndian.Uint64(decoded[:]))
		return crc32.ChecksumIEEE(decoded[:12]) == binary.BigEndian.Uint32(decoded[12:]) && timestamp >= now-120 && timestamp <= now+120
	})
	if err != nil {
		return err
	}
	// Reserve after AuthID validation and before upstream parsing. A failed or
	// interrupted request keeps its reservation: it cannot reopen the replay gap.
	if !s.replay.Accept(replayKey{user: match.Index, id: header}) {
		match.Reject()
		return errAuthReplay
	}
	ctx = context.WithValue(ctx, matchKey{}, match)
	err = s.users[match.Index].service.NewConnection(ctx, authscan.ReplayPrefix(conn, header[:]), source, onClose)
	if authscan.Rejected(err) {
		match.Reject()
	}
	return err
}
func (s *server) NewConnectionEx(ctx context.Context, conn net.Conn, src, dst M.Socksaddr, close N.CloseHandlerFunc) {
	ctx.Value(matchKey{}).(*authscan.Match[netip.Addr]).Accept()
	s.handler.NewConnectionEx(ctx, conn, src, dst, close)
}
func (s *server) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, src, dst M.Socksaddr, close N.CloseHandlerFunc) {
	ctx.Value(matchKey{}).(*authscan.Match[netip.Addr]).Accept()
	s.handler.NewPacketConnectionEx(ctx, conn, src, dst, close)
}
