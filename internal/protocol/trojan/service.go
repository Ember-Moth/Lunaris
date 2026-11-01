// SPDX-License-Identifier: GPL-3.0-only
package trojan

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type Service struct {
	Users   map[string]string
	Handler protocol.RelayHandler
}

func New(users, passwords []string, h protocol.RelayHandler) *Service {
	s := &Service{Users: make(map[string]string), Handler: h}
	for i, p := range passwords {
		sum := sha256.Sum224([]byte(p))
		s.Users[hex.EncodeToString(sum[:])] = users[i]
	}
	return s
}
func crlf(r io.Reader) error {
	var b [2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return err
	}
	if b != [2]byte{'\r', '\n'} {
		return errors.New("invalid Trojan delimiter")
	}
	return nil
}
func (s *Service) NewConnection(ctx context.Context, c net.Conn, src M.Socksaddr, onClose N.CloseHandlerFunc) error {
	var hash [56]byte
	if _, err := io.ReadFull(c, hash[:]); err != nil {
		return err
	}
	user, ok := s.Users[string(hash[:])]
	if !ok {
		return errors.New("invalid Trojan credential")
	}
	if err := crlf(c); err != nil {
		return err
	}
	var cmd [1]byte
	if _, err := io.ReadFull(c, cmd[:]); err != nil {
		return err
	}
	dst, err := M.SocksaddrSerializer.ReadAddrPort(c)
	if err != nil {
		return err
	}
	if err = crlf(c); err != nil {
		return err
	}
	ctx = auth.ContextWithUser(ctx, user)
	switch cmd[0] {
	case 1:
		s.Handler.NewConnectionEx(ctx, c, src, dst, onClose)
	case 3:
		s.Handler.NewPacketConnectionEx(ctx, &packetConn{Conn: c}, src, dst, onClose)
	default:
		return errors.New("unsupported Trojan command")
	}
	return nil
}

type packetConn struct {
	net.Conn
	writeMu sync.Mutex
}

func (c *packetConn) ReadPacket(b *buf.Buffer) (M.Socksaddr, error) {
	dst, err := M.SocksaddrSerializer.ReadAddrPort(c.Conn)
	if err != nil {
		return dst, err
	}
	var length uint16
	if err = binary.Read(c.Conn, binary.BigEndian, &length); err != nil {
		return dst, err
	}
	if err = crlf(c.Conn); err != nil {
		return dst, err
	}
	_, err = b.ReadFullFrom(c.Conn, int(length))
	return dst, err
}
func (c *packetConn) WritePacket(b *buf.Buffer, dst M.Socksaddr) error {
	defer b.Release()
	if b.Len() > 65535 {
		return errors.New("Trojan packet too large")
	}
	header := buf.NewSize(M.SocksaddrSerializer.AddrPortLen(dst) + 4 + b.Len())
	defer header.Release()
	if err := M.SocksaddrSerializer.WriteAddrPort(header, dst); err != nil {
		return err
	}
	_ = binary.Write(header, binary.BigEndian, uint16(b.Len()))
	_, _ = header.Write([]byte{'\r', '\n'})
	_, _ = header.Write(b.Bytes())
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_, err := c.Conn.Write(header.Bytes())
	return err
}
