// SPDX-License-Identifier: GPL-3.0-or-later
// Derived from SagerNet/sing-vmess and Polaris; see THIRD_PARTY_NOTICES.md.
package vless

import (
	std_bufio "bufio"
	"context"
	"encoding/binary"
	"io"
	"math"
	"net"
	"os"
	"sync"
	"time"

	vmess "github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const DefaultMaxMuxStreams = 128

type MuxOptions struct {
	MaxStreams int
}

func (options MuxOptions) normalized() MuxOptions {
	if options.MaxStreams <= 0 {
		options.MaxStreams = DefaultMaxMuxStreams
	}
	return options
}

func HandleMuxConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, handler Handler) error {
	return HandleMuxConnectionWithOptions(ctx, conn, source, handler, MuxOptions{})
}

func HandleMuxConnectionWithOptions(ctx context.Context, conn net.Conn, source M.Socksaddr, handler Handler, options MuxOptions) error {
	options = options.normalized()
	ctx, cancel := context.WithCancelCause(ctx)
	session := &serverSession{
		ctx:          ctx,
		source:       source,
		conn:         conn,
		directWriter: bufio.NewExtendedWriter(conn),
		handler:      handler,
		streams:      make(map[uint16]*serverStream),
		writer:       std_bufio.NewWriter(conn),
		maxStreams:   options.MaxStreams,
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		session.cleanup(ctx.Err())
	}()
	err := session.recvLoop(cancel)
	<-done
	return err
}

type serverSession struct {
	ctx          context.Context
	source       M.Socksaddr
	conn         net.Conn
	directWriter N.ExtendedWriter
	handler      Handler
	streamAccess sync.RWMutex
	streams      map[uint16]*serverStream
	writer       *std_bufio.Writer
	writeAccess  sync.Mutex
	maxStreams   int
}

type serverStream struct {
	network     byte
	destination M.Socksaddr
	pipe        interface {
		io.Writer
		CloseWithError(error) error
	}
}

func (c *serverSession) recvLoop(cancel context.CancelCauseFunc) error {
	for {
		err := c.recv()
		if err != nil {
			cancel(err)
			return E.Cause(err, "mux connection closed")
		}
	}
}

func (c *serverSession) cleanup(err error) {
	c.streamAccess.Lock()
	for _, stream := range c.streams {
		_ = stream.pipe.CloseWithError(err)
	}
	clear(c.streams)
	c.streamAccess.Unlock()
}

func (c *serverSession) recv() error {
	var length uint16
	err := binary.Read(c.conn, binary.BigEndian, &length)
	if err != nil {
		return E.Cause(err, "read frame header")
	}
	if length < 4 || int(length) > 5+M.MaxSocksaddrLength {
		return E.New("invalid mux frame length: ", length)
	}

	var sessionID uint16
	err = binary.Read(c.conn, binary.BigEndian, &sessionID)
	if err != nil {
		return err
	}

	var status byte
	err = binary.Read(c.conn, binary.BigEndian, &status)
	if err != nil {
		return err
	}

	var option byte
	err = binary.Read(c.conn, binary.BigEndian, &option)
	if err != nil {
		return err
	}

	var network byte
	var destination M.Socksaddr
	if length > 4 {
		limitReader := io.LimitReader(c.conn, int64(length-4))
		err = binary.Read(limitReader, binary.BigEndian, &network)
		if err != nil {
			return err
		}
		destination, err = vmess.AddressSerializer.ReadAddrPort(limitReader)
		if err != nil {
			return err
		}
		if limitReader.(*io.LimitedReader).N > 0 {
			_, err = io.Copy(io.Discard, limitReader)
			if err != nil {
				return err
			}
		}
	}

	var stream *serverStream
	switch status {
	case vmess.StatusNew:
		switch network {
		case vmess.NetworkTCP, vmess.NetworkUDP:
		default:
			return E.New("bad network: ", network)
		}
		pipeIn, out := net.Pipe()
		pipeOut := &muxPipeWriter{out}
		stream = &serverStream{
			network,
			destination,
			pipeOut,
		}
		c.streamAccess.Lock()
		if _, loaded := c.streams[sessionID]; loaded {
			c.streamAccess.Unlock()
			_ = pipeIn.Close()
			_ = pipeOut.Close()
			return E.New("duplicate mux session: ", sessionID)
		}
		if len(c.streams) >= c.maxStreams {
			c.streamAccess.Unlock()
			_ = pipeIn.Close()
			_ = pipeOut.Close()
			return E.New("too many mux streams: ", c.maxStreams)
		}
		c.streams[sessionID] = stream
		c.streamAccess.Unlock()
		go func() {
			if network == vmess.NetworkTCP {
				conn := &serverMuxConn{
					sessionID,
					pipeIn,
					c,
				}
				c.handler.NewConnectionEx(c.ctx, conn, c.source, destination, nil)
			} else {
				conn := &serverMuxPacketConn{
					sessionID,
					pipeIn,
					c,
					destination,
				}
				c.handler.NewPacketConnectionEx(c.ctx, conn, c.source, destination, nil)
			}
		}()
	case vmess.StatusKeep:
		var loaded bool
		c.streamAccess.RLock()
		stream, loaded = c.streams[sessionID]
		c.streamAccess.RUnlock()
		if !loaded {
			if err := c.syncClose(sessionID, true); err != nil {
				return err
			}
		}
	case vmess.StatusEnd:
		if option&vmess.OptionError == vmess.OptionError {
			err = E.New("remote closed wth error")
		}
		c.localClose(sessionID, err)
	case vmess.StatusKeepAlive:
	default:
		return E.New("bad session status: ", status)
	}

	if option&vmess.OptionData != vmess.OptionData {
		return nil
	}

	err = binary.Read(c.conn, binary.BigEndian, &length)
	if err != nil {
		return err
	}

	if length == 0 && (stream == nil || stream.network != vmess.NetworkUDP) {
		return nil
	}

	if stream == nil {
		return common.Error(io.CopyN(io.Discard, c.conn, int64(length)))
	}

	data := buf.NewSize(int(length))
	defer data.Release()

	_, err = data.ReadFullFrom(c.conn, int(length))
	if err != nil {
		return err
	}

	if !destination.IsValid() {
		destination = stream.destination
	}

	err = c.recvTo(stream, data, destination)
	if err != nil {
		return c.close(sessionID, err)
	}

	return nil
}

func (c *serverSession) recvTo(stream *serverStream, data *buf.Buffer, destination M.Socksaddr) error {
	if stream.network == vmess.NetworkTCP {
		return common.Error(stream.pipe.Write(data.Bytes()))
	} else {
		err := binary.Write(stream.pipe, binary.BigEndian, uint16(data.Len()))
		if err != nil {
			return err
		}
		_, err = stream.pipe.Write(data.Bytes())
		if err != nil {
			return err
		}
		err = vmess.AddressSerializer.WriteAddrPort(stream.pipe, destination)
		if err != nil {
			return err
		}
		return nil
	}
}

func (c *serverSession) syncWrite(sessionID uint16, data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	written := 0
	for len(data) > 0 {
		chunk := data
		if len(chunk) > math.MaxUint16 {
			chunk = chunk[:math.MaxUint16]
		}
		if err := c.writeFrame(sessionID, chunk); err != nil {
			return written, err
		}
		written += len(chunk)
		data = data[len(chunk):]
	}
	// Arrival sequence is not mutex acquisition order. Every writer must
	// flush its own completed batch before releasing ownership.
	if err := c.writer.Flush(); err != nil {
		return written, err
	}
	return written, nil
}

func (c *serverSession) writeFrame(sessionID uint16, data []byte) error {
	err := binary.Write(c.writer, binary.BigEndian, uint16(4))
	if err != nil {
		return err
	}
	err = binary.Write(c.writer, binary.BigEndian, sessionID)
	if err != nil {
		return err
	}
	err = binary.Write(c.writer, binary.BigEndian, uint8(vmess.StatusKeep))
	if err != nil {
		return err
	}
	err = binary.Write(c.writer, binary.BigEndian, uint8(vmess.OptionData))
	if err != nil {
		return err
	}
	err = binary.Write(c.writer, binary.BigEndian, uint16(len(data)))
	if err != nil {
		return err
	}
	return common.Error(c.writer.Write(data))
}

func (c *serverSession) syncWritePacket(sessionID uint16, data []byte, destination M.Socksaddr) (int, error) {
	if len(data) > math.MaxUint16 {
		return 0, os.ErrInvalid
	}
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	err := c.writePacketFrame(sessionID, data, destination)
	if err != nil {
		return 0, err
	}
	if err = c.writer.Flush(); err != nil {
		return 0, err
	}
	return len(data), nil
}

func (c *serverSession) writePacketFrame(sessionID uint16, data []byte, destination M.Socksaddr) error {
	err := binary.Write(c.writer, binary.BigEndian, uint16(5+vmess.AddressSerializer.AddrPortLen(destination)))
	if err != nil {
		return err
	}
	err = binary.Write(c.writer, binary.BigEndian, sessionID)
	if err != nil {
		return err
	}
	err = binary.Write(c.writer, binary.BigEndian, uint8(vmess.StatusKeep))
	if err != nil {
		return err
	}
	err = binary.Write(c.writer, binary.BigEndian, uint8(vmess.OptionData))
	if err != nil {
		return err
	}
	if destination.IsValid() {
		err = binary.Write(c.writer, binary.BigEndian, uint8(vmess.NetworkUDP))
		if err != nil {
			return err
		}
		err = vmess.AddressSerializer.WriteAddrPort(c.writer, destination)
		if err != nil {
			return err
		}
	}
	err = binary.Write(c.writer, binary.BigEndian, uint16(len(data)))
	if err != nil {
		return err
	}
	return common.Error(c.writer.Write(data))
}

func (c *serverSession) close(sessionID uint16, err error) error {
	if c.localClose(sessionID, err) {
		return c.syncClose(sessionID, err != nil)
	}
	return nil
}

func (c *serverSession) localClose(sessionID uint16, err error) bool {
	var closed bool
	c.streamAccess.Lock()
	if session, loaded := c.streams[sessionID]; loaded {
		delete(c.streams, sessionID)
		_ = session.pipe.CloseWithError(err)
		closed = true
	}
	c.streamAccess.Unlock()
	return closed
}

func (c *serverSession) syncClose(sessionID uint16, hasError bool) error {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	err := c.writeCloseFrame(sessionID, hasError)
	if err != nil {
		return err
	}
	if err = c.writer.Flush(); err != nil {
		return err
	}
	return nil
}

func (c *serverSession) writeCloseFrame(sessionID uint16, hasError bool) error {
	err := binary.Write(c.writer, binary.BigEndian, uint16(4))
	if err != nil {
		return err
	}
	err = binary.Write(c.writer, binary.BigEndian, sessionID)
	if err != nil {
		return err
	}
	err = binary.Write(c.writer, binary.BigEndian, uint8(vmess.StatusEnd))
	if err != nil {
		return err
	}
	var option uint8
	if hasError {
		option = vmess.OptionError
	}
	err = binary.Write(c.writer, binary.BigEndian, option)
	return err
}

type serverMuxConn struct {
	sessionID uint16
	pipe      io.ReadCloser
	session   *serverSession
}

func (c *serverMuxConn) Read(b []byte) (n int, err error) {
	return c.pipe.Read(b)
}

func (c *serverMuxConn) Write(b []byte) (n int, err error) {
	return c.session.syncWrite(c.sessionID, b)
}

func (c *serverMuxConn) WriteBuffer(buffer *buf.Buffer) error {
	defer buffer.Release()
	_, err := c.session.syncWrite(c.sessionID, buffer.Bytes())
	return err
}

func (c *serverMuxConn) FrontHeadroom() int {
	return 8
}

func (c *serverMuxConn) UpstreamWriter() any {
	return c.session.directWriter
}

func (c *serverMuxConn) Close() error {
	_ = c.pipe.Close()
	return c.session.close(c.sessionID, nil)
}

func (c *serverMuxConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *serverMuxConn) RemoteAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *serverMuxConn) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *serverMuxConn) SetReadDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *serverMuxConn) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *serverMuxConn) NeedAdditionalReadDeadline() bool {
	return true
}

var _ vmess.PacketConn = (*serverMuxPacketConn)(nil)

type serverMuxPacketConn struct {
	sessionID   uint16
	pipe        io.ReadCloser
	session     *serverSession
	destination M.Socksaddr
}

func (c *serverMuxPacketConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return
}

func (c *serverMuxPacketConn) Write(b []byte) (n int, err error) {
	return c.WriteTo(b, c.destination)
}

func (c *serverMuxPacketConn) RemoteAddr() net.Addr {
	return c.destination.UDPAddr()
}

func (c *serverMuxPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	var length uint16
	err = binary.Read(c.pipe, binary.BigEndian, &length)
	if err != nil {
		return
	}
	if int(length) > len(p) {
		if discardErr := discardMuxPacket(c.pipe, int64(length)); discardErr != nil {
			return 0, nil, discardErr
		}
		return 0, nil, E.Extend(io.ErrShortBuffer, "mux need ", length)
	}
	n, err = io.ReadFull(c.pipe, p[:length])
	if err == nil {
		addr, err = vmess.AddressSerializer.ReadAddrPort(c.pipe)
	}
	return
}

func (c *serverMuxPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	var length uint16
	err = binary.Read(c.pipe, binary.BigEndian, &length)
	if err != nil {
		return
	}
	if int(length) > buffer.FreeLen() {
		if discardErr := discardMuxPacket(c.pipe, int64(length)); discardErr != nil {
			return M.Socksaddr{}, discardErr
		}
		return M.Socksaddr{}, E.Extend(io.ErrShortBuffer, "mux need ", length)
	}
	_, err = buffer.ReadFullFrom(c.pipe, int(length))
	if err == nil {
		destination, err = vmess.AddressSerializer.ReadAddrPort(c.pipe)
		if err == nil {
			destination = destination.Unwrap()
		}
	}
	return
}

func discardMuxPacket(reader io.Reader, length int64) error {
	if _, err := io.CopyN(io.Discard, reader, length); err != nil {
		return err
	}
	_, err := vmess.AddressSerializer.ReadAddrPort(reader)
	return err
}

func (c *serverMuxPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return c.session.syncWritePacket(c.sessionID, p, M.SocksaddrFromNet(addr))
}

func (c *serverMuxPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	_, err := c.session.syncWritePacket(c.sessionID, buffer.Bytes(), destination)
	return err
}

func (c *serverMuxPacketConn) FrontHeadroom() int {
	return 9 + M.MaxSocksaddrLength
}

func (c *serverMuxPacketConn) UpstreamWriter() any {
	return c.session.directWriter
}

func (c *serverMuxPacketConn) Close() error {
	_ = c.pipe.Close()
	return c.session.close(c.sessionID, nil)
}

func (c *serverMuxPacketConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *serverMuxPacketConn) SetDeadline(t time.Time) error {
	return c.SetReadDeadline(t)
}

func (c *serverMuxPacketConn) SetReadDeadline(t time.Time) error {
	if conn, ok := c.pipe.(net.Conn); ok {
		return conn.SetReadDeadline(t)
	}
	return os.ErrInvalid
}

func (c *serverMuxPacketConn) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *serverMuxPacketConn) NeedAdditionalReadDeadline() bool {
	return true
}

type muxPipeWriter struct{ net.Conn }

func (p *muxPipeWriter) CloseWithError(error) error { return p.Close() }
