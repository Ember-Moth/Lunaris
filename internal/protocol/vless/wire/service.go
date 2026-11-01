// SPDX-License-Identifier: GPL-3.0-or-later
// Derived from SagerNet/sing-vmess and Polaris; see THIRD_PARTY_NOTICES.md.
package vless

import (
	"context"
	"encoding/binary"
	"io"
	"math"
	"net"
	"os"
	"sync"

	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/gofrs/uuid/v5"
)

type Service[T comparable] struct {
	users   atomic.TypedValue[*userGeneration[T]]
	logger  logger.Logger
	handler Handler
}

type userGeneration[T comparable] struct {
	users map[[16]byte]userRecord[T]
}

type userRecord[T comparable] struct {
	identity T
	flow     string
}

type Handler interface {
	N.TCPConnectionHandlerEx
	N.UDPConnectionHandlerEx
}

func NewService[T comparable](logger logger.Logger, handler Handler) *Service[T] {
	service := &Service[T]{logger: logger, handler: handler}
	service.users.Store(&userGeneration[T]{users: make(map[[16]byte]userRecord[T])})
	return service
}

func (s *Service[T]) UpdateUsers(userList []T, userUUIDList []string, userFlowList []string) error {
	if len(userList) != len(userUUIDList) || len(userList) != len(userFlowList) {
		return E.New("mismatched VLESS user, UUID and flow count")
	}
	userMap := make(map[[16]byte]userRecord[T], len(userList))
	seenUsers := make(map[T]struct{}, len(userList))
	for i, userName := range userList {
		if _, loaded := seenUsers[userName]; loaded {
			return E.New("duplicate VLESS user")
		}
		userID, err := uuid.FromString(userUUIDList[i])
		if err != nil {
			return E.New("invalid VLESS UUID")
		}
		if _, loaded := userMap[userID]; loaded {
			return E.New("duplicate VLESS UUID")
		}
		seenUsers[userName] = struct{}{}
		userMap[userID] = userRecord[T]{identity: userName, flow: userFlowList[i]}
	}
	s.users.Store(&userGeneration[T]{users: userMap})
	return nil
}

func (s *Service[T]) NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) error {
	request, err := ReadRequest(conn)
	if err != nil {
		return err
	}
	generation := s.users.Load()
	user, loaded := generation.users[request.UUID]
	if !loaded {
		return E.New("VLESS authentication failed")
	}
	ctx = auth.ContextWithUser(ctx, user.identity)
	userFlow := user.flow
	if request.Flow == FlowVision && request.Command == vmess.NetworkUDP {
		return E.New(FlowVision, " flow does not support UDP")
	} else if request.Flow != userFlow {
		return E.New("flow mismatch: expected ", flowName(userFlow), ", but got ", flowName(request.Flow))
	}

	if request.Command == vmess.CommandUDP {
		s.handler.NewPacketConnectionEx(ctx, &serverPacketConn{ExtendedConn: bufio.NewExtendedConn(conn), destination: request.Destination}, source, request.Destination, onClose)
		return nil
	}
	responseConn := &serverConn{ExtendedConn: bufio.NewExtendedConn(conn)}
	switch userFlow {
	case FlowVision:
		conn, err = NewVisionConn(responseConn, conn, request.UUID, s.logger)
		if err != nil {
			return E.Cause(err, "initialize vision")
		}
	case "":
		conn = responseConn
	default:
		return E.New("unknown flow: ", userFlow)
	}
	switch request.Command {
	case vmess.CommandTCP:
		s.handler.NewConnectionEx(ctx, conn, source, request.Destination, onClose)
		return nil
	case vmess.CommandMux:
		return HandleMuxConnection(ctx, conn, source, s.handler)
	default:
		return E.New("unknown command: ", request.Command)
	}
}

func flowName(value string) string {
	if value == "" {
		return "none"
	}
	return value
}

type serverConn struct {
	N.ExtendedConn
	responseWritten bool
}

func (c *serverConn) Read(b []byte) (n int, err error) {
	return c.ExtendedConn.Read(b)
}

func (c *serverConn) Write(b []byte) (n int, err error) {
	if !c.responseWritten {
		buffer := buf.NewSize(2 + len(b))
		buffer.WriteByte(Version)
		buffer.WriteByte(0)
		buffer.Write(b)
		_, err = c.ExtendedConn.Write(buffer.Bytes())
		buffer.Release()
		if err == nil {
			n = len(b)
		}
		c.responseWritten = true
		return
	}
	return c.ExtendedConn.Write(b)
}

func (c *serverConn) WriteBuffer(buffer *buf.Buffer) error {
	if !c.responseWritten {
		header := buffer.ExtendHeader(2)
		header[0] = Version
		header[1] = 0
		c.responseWritten = true
	}
	return c.ExtendedConn.WriteBuffer(buffer)
}

func (c *serverConn) FrontHeadroom() int {
	if c.responseWritten {
		return 0
	}
	return 2
}

func (c *serverConn) ReaderReplaceable() bool {
	return true
}

func (c *serverConn) WriterReplaceable() bool {
	return c.responseWritten
}

func (c *serverConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *serverConn) Upstream() any {
	return c.ExtendedConn
}

type serverPacketConn struct {
	N.ExtendedConn
	responseWritten bool
	destination     M.Socksaddr
	writeMu         sync.Mutex
	batchVectors    []*buf.Buffer
}

func (c *serverPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	var packetLen uint16
	err = binary.Read(c.ExtendedConn, binary.BigEndian, &packetLen)
	if err != nil {
		return
	}
	if len(p) < int(packetLen) {
		if _, discardErr := io.CopyN(io.Discard, c.ExtendedConn, int64(packetLen)); discardErr != nil {
			err = discardErr
			return
		}
		err = io.ErrShortBuffer
		return
	}
	n, err = io.ReadFull(c.ExtendedConn, p[:packetLen])
	if err != nil {
		return
	}
	if c.destination.IsFqdn() {
		addr = c.destination
	} else {
		addr = c.destination.UDPAddr()
	}
	return
}

func (c *serverPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return bufio.WritePacketBuffer(c, buf.As(p), M.SocksaddrFromNet(addr))
}

func (c *serverPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	var packetLen uint16
	err = binary.Read(c.ExtendedConn, binary.BigEndian, &packetLen)
	if err != nil {
		return
	}

	_, err = buffer.ReadFullFrom(c.ExtendedConn, int(packetLen))
	if err != nil {
		return
	}

	destination = c.destination
	return
}

func (c *serverPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	dataLen := buffer.Len()
	if dataLen > math.MaxUint16 {
		buffer.Release()
		return E.New("VLESS UDP packet too large: ", dataLen)
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	headerLength := 2
	if !c.responseWritten {
		headerLength += 2
		c.responseWritten = true
	}
	packetLen := buffer.Len()
	header := buffer.ExtendHeader(headerLength)
	if headerLength == 4 {
		header[0] = Version
		header[1] = 0
		header = header[2:]
	}
	binary.BigEndian.PutUint16(header, uint16(packetLen))
	return c.ExtendedConn.WriteBuffer(buffer)
}

func (c *serverPacketConn) CreatePacketBatchWriter() (N.PacketBatchWriter, bool) {
	return c, true
}

func (c *serverPacketConn) WritePacketBatch(buffers []*buf.Buffer, destinations []M.Socksaddr) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if len(buffers) == 0 || len(buffers) != len(destinations) {
		buf.ReleaseMulti(buffers)
		return os.ErrInvalid
	}
	for _, buffer := range buffers {
		if buffer.Len() > math.MaxUint16 {
			buf.ReleaseMulti(buffers)
			return os.ErrInvalid
		}
	}
	clear(c.batchVectors)
	c.batchVectors = c.batchVectors[:0]
	if cap(c.batchVectors) < len(buffers)+1 {
		c.batchVectors = make([]*buf.Buffer, 0, len(buffers)+1)
	}
	if !c.responseWritten {
		header := buf.NewSize(2)
		_ = header.WriteByte(Version)
		_ = header.WriteByte(0)
		c.batchVectors = append(c.batchVectors, header)
		c.responseWritten = true
	}
	for _, buffer := range buffers {
		packetLen := buffer.Len()
		binary.BigEndian.PutUint16(buffer.ExtendHeader(2), uint16(packetLen))
		c.batchVectors = append(c.batchVectors, buffer)
	}
	err := bufio.NewVectorisedWriter(c.ExtendedConn).WriteVectorised(c.batchVectors)
	clear(c.batchVectors)
	c.batchVectors = c.batchVectors[:0]
	return err
}

func (c *serverPacketConn) FrontHeadroom() int {
	return 4
}

func (c *serverPacketConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *serverPacketConn) Upstream() any {
	return c.ExtendedConn
}

var _ N.PacketBatchWriteCreator = (*serverPacketConn)(nil)
