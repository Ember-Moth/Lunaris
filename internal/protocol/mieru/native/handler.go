// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package native

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	socksConnect      = 1
	socksUDPAssociate = 3
)

func (s *Server) handle(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(s.option.HandshakeTimeout))
	command, destination, err := readSocksRequest(conn)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		s.fail(conn, fmt.Errorf("sing-mieru: read request: %w", err))
		return
	}
	userConn, ok := conn.(interface{ UserName() string })
	if !ok || userConn.UserName() == "" {
		s.fail(conn, errors.New("sing-mieru: authenticated user is missing"))
		return
	}
	parent := s.ctx
	if contextual, ok := conn.(interface{ Context() context.Context }); ok && contextual.Context() != nil {
		parent = contextual.Context()
	}
	ctx := auth.ContextWithUser(parent, userConn.UserName())
	if authenticated, ok := conn.(interface{ Authenticated() }); ok {
		authenticated.Authenticated()
	}
	if err = writeSocksResponse(conn); err != nil {
		s.fail(conn, fmt.Errorf("sing-mieru: write response: %w", err))
		return
	}
	source := M.SocksaddrFromNet(conn.RemoteAddr()).Unwrap()
	switch command {
	case socksConnect:
		s.option.TCPHandler.NewConnectionEx(ctx, conn, source, destination, nil)
	case socksUDPAssociate:
		if s.option.UDPHandler == nil {
			s.fail(conn, errors.New("sing-mieru: UDP handler is unavailable"))
			return
		}
		packet := newPacketConn(conn)
		_ = conn.SetReadDeadline(time.Now().Add(s.option.HandshakeTimeout))
		first := buf.NewSize(65535)
		target, err := packet.ReadPacket(first)
		if err != nil {
			first.Release()
			s.fail(conn, err)
			return
		}
		_ = conn.SetReadDeadline(time.Time{})
		s.option.UDPHandler.NewPacketConnectionEx(ctx, bufio.NewCachedPacketConn(packet, first, target), source, target, nil)
	default:
		s.fail(conn, errors.New("sing-mieru: unsupported command"))
	}
}

func (s *Server) fail(conn net.Conn, err error) {
	_ = conn.Close()
	s.report(err)
}

func readSocksRequest(reader io.Reader) (byte, M.Socksaddr, error) {
	var head [4]byte
	if _, err := io.ReadFull(reader, head[:]); err != nil {
		return 0, M.Socksaddr{}, err
	}
	if head[0] != 5 || head[2] != 0 {
		return 0, M.Socksaddr{}, errors.New("invalid SOCKS5 request")
	}
	var host string
	switch head[3] {
	case 1:
		var address [4]byte
		if _, err := io.ReadFull(reader, address[:]); err != nil {
			return 0, M.Socksaddr{}, err
		}
		host = net.IP(address[:]).String()
	case 4:
		var address [16]byte
		if _, err := io.ReadFull(reader, address[:]); err != nil {
			return 0, M.Socksaddr{}, err
		}
		host = net.IP(address[:]).String()
	case 3:
		var size [1]byte
		if _, err := io.ReadFull(reader, size[:]); err != nil {
			return 0, M.Socksaddr{}, err
		}
		name := make([]byte, int(size[0]))
		if _, err := io.ReadFull(reader, name); err != nil {
			return 0, M.Socksaddr{}, err
		}
		host = string(name)
	default:
		return 0, M.Socksaddr{}, errors.New("invalid SOCKS5 address type")
	}
	var port [2]byte
	if _, err := io.ReadFull(reader, port[:]); err != nil {
		return 0, M.Socksaddr{}, err
	}
	destination := M.ParseSocksaddrHostPort(host, binary.BigEndian.Uint16(port[:]))
	if !destination.IsValid() || (destination.Port == 0 && head[1] != socksUDPAssociate) {
		return 0, M.Socksaddr{}, errors.New("invalid SOCKS5 destination")
	}
	return head[1], destination.Unwrap(), nil
}

func writeSocksResponse(writer io.Writer) error {
	_, err := writer.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}
