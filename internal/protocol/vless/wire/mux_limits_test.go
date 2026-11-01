// SPDX-License-Identifier: GPL-3.0-or-later
// Derived from SagerNet/sing-vmess and Polaris; see THIRD_PARTY_NOTICES.md.
package vless

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"strings"
	"testing"
	"time"

	vmess "github.com/sagernet/sing-vmess"
	S "github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestMuxRejectsDuplicateSessionID(t *testing.T) {
	pipeIn, pipeOut := io.Pipe()
	defer pipeIn.Close()
	defer pipeOut.Close()
	session := newMuxTestSession(muxNewFrame(t, 7), 2)
	session.streams[7] = &serverStream{network: vmess.NetworkTCP, pipe: pipeOut}
	if err := session.recv(); err == nil || !strings.Contains(err.Error(), "duplicate mux session") {
		t.Fatalf("recv error = %v", err)
	}
}

func TestMuxRejectsStreamsOverLimit(t *testing.T) {
	pipeIn, pipeOut := io.Pipe()
	defer pipeIn.Close()
	defer pipeOut.Close()
	session := newMuxTestSession(muxNewFrame(t, 8), 1)
	session.streams[7] = &serverStream{network: vmess.NetworkTCP, pipe: pipeOut}
	if err := session.recv(); err == nil || !strings.Contains(err.Error(), "too many mux streams") {
		t.Fatalf("recv error = %v", err)
	}
}

func TestMuxRejectsInvalidFrameLengthBeforeReadingHeader(t *testing.T) {
	var wire bytes.Buffer
	_ = binary.Write(&wire, binary.BigEndian, uint16(3))
	session := newMuxTestSession(wire.Bytes(), 1)
	if err := session.recv(); err == nil || !strings.Contains(err.Error(), "invalid mux frame length") {
		t.Fatalf("recv error = %v", err)
	}
}

func TestMuxUnknownSessionCloseIsWrittenSynchronously(t *testing.T) {
	var wire bytes.Buffer
	_ = binary.Write(&wire, binary.BigEndian, uint16(4))
	_ = binary.Write(&wire, binary.BigEndian, uint16(9))
	_ = wire.WriteByte(vmess.StatusKeep)
	_ = wire.WriteByte(0)
	session := newMuxTestSession(wire.Bytes(), 1)
	if err := session.recv(); err != nil {
		t.Fatal(err)
	}
	output := session.conn.(*muxTestConn).output.Bytes()
	if len(output) != 6 || binary.BigEndian.Uint16(output[:2]) != 4 ||
		binary.BigEndian.Uint16(output[2:4]) != 9 || output[4] != vmess.StatusEnd || output[5] != vmess.OptionError {
		t.Fatalf("close frame = %v", output)
	}
}

func TestMuxTCPWriteSplitsPayloadAtFrameLimit(t *testing.T) {
	session := newMuxTestSession(nil, 1)
	payload := make([]byte, 70_000)
	written, err := session.syncWrite(7, payload)
	if err != nil || written != len(payload) {
		t.Fatalf("syncWrite = %d, %v", written, err)
	}
	reader := bytes.NewReader(session.conn.(*muxTestConn).output.Bytes())
	for index, wantLength := range []int{math.MaxUint16, len(payload) - math.MaxUint16} {
		var frameLength, sessionID uint16
		var status, option byte
		if err = binary.Read(reader, binary.BigEndian, &frameLength); err != nil {
			t.Fatal(err)
		}
		if err = binary.Read(reader, binary.BigEndian, &sessionID); err != nil {
			t.Fatal(err)
		}
		if status, err = reader.ReadByte(); err != nil {
			t.Fatal(err)
		}
		if option, err = reader.ReadByte(); err != nil {
			t.Fatal(err)
		}
		var payloadLength uint16
		if err = binary.Read(reader, binary.BigEndian, &payloadLength); err != nil {
			t.Fatal(err)
		}
		if frameLength != 4 || sessionID != 7 || status != vmess.StatusKeep || option != vmess.OptionData || int(payloadLength) != wantLength {
			t.Fatalf("frame %d = len %d session %d status %d option %d payload %d", index, frameLength, sessionID, status, option, payloadLength)
		}
		if _, err = io.CopyN(io.Discard, reader, int64(payloadLength)); err != nil {
			t.Fatal(err)
		}
	}
	if reader.Len() != 0 {
		t.Fatalf("trailing mux bytes = %d", reader.Len())
	}
}

func TestMuxPacketShortReadKeepsFrameAlignment(t *testing.T) {
	pipeIn, pipeOut := io.Pipe()
	defer pipeIn.Close()
	defer pipeOut.Close()
	conn := &serverMuxPacketConn{pipe: pipeIn}
	destination := M.ParseSocksaddr("192.0.2.53:53")
	writeDone := make(chan error, 1)
	go func() {
		for _, payload := range [][]byte{[]byte("oversized"), []byte("ok")} {
			if err := binary.Write(pipeOut, binary.BigEndian, uint16(len(payload))); err != nil {
				writeDone <- err
				return
			}
			if _, err := pipeOut.Write(payload); err != nil {
				writeDone <- err
				return
			}
			if err := vmess.AddressSerializer.WriteAddrPort(pipeOut, destination); err != nil {
				writeDone <- err
				return
			}
		}
		writeDone <- nil
	}()
	if _, _, err := conn.ReadFrom(make([]byte, 2)); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("short read error = %v", err)
	}
	output := make([]byte, 2)
	n, addr, err := conn.ReadFrom(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(output[:n]) != "ok" || M.SocksaddrFromNet(addr).Unwrap() != destination {
		t.Fatalf("second packet = %q from %v", output[:n], addr)
	}
	if err = <-writeDone; err != nil {
		t.Fatal(err)
	}
}

func newMuxTestSession(input []byte, maxStreams int) *serverSession {
	conn := &muxTestConn{reader: bytes.NewReader(input)}
	return &serverSession{
		ctx: context.Background(), conn: conn, source: M.ParseSocksaddr("192.0.2.1:1234"),
		directWriter: S.NewExtendedWriter(conn), handler: muxNoopHandler{}, streams: make(map[uint16]*serverStream),
		writer: bufio.NewWriter(conn), maxStreams: maxStreams,
	}
}

func muxNewFrame(t *testing.T, sessionID uint16) []byte {
	t.Helper()
	destination := M.ParseSocksaddr("example.com:443")
	var wire bytes.Buffer
	_ = binary.Write(&wire, binary.BigEndian, uint16(5+vmess.AddressSerializer.AddrPortLen(destination)))
	_ = binary.Write(&wire, binary.BigEndian, sessionID)
	_ = wire.WriteByte(vmess.StatusNew)
	_ = wire.WriteByte(0)
	_ = wire.WriteByte(vmess.NetworkTCP)
	if err := vmess.AddressSerializer.WriteAddrPort(&wire, destination); err != nil {
		t.Fatal(err)
	}
	return wire.Bytes()
}

type muxTestConn struct {
	reader *bytes.Reader
	output bytes.Buffer
}

func (conn *muxTestConn) Read(p []byte) (int, error)  { return conn.reader.Read(p) }
func (conn *muxTestConn) Write(p []byte) (int, error) { return conn.output.Write(p) }
func (*muxTestConn) Close() error                     { return nil }
func (*muxTestConn) LocalAddr() net.Addr              { return nil }
func (*muxTestConn) RemoteAddr() net.Addr             { return nil }
func (*muxTestConn) SetDeadline(time.Time) error      { return nil }
func (*muxTestConn) SetReadDeadline(time.Time) error  { return nil }
func (*muxTestConn) SetWriteDeadline(time.Time) error { return nil }

type muxNoopHandler struct{}

func (muxNoopHandler) NewConnectionEx(context.Context, net.Conn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc) {
}

func (muxNoopHandler) NewPacketConnectionEx(context.Context, N.PacketConn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc) {
}
