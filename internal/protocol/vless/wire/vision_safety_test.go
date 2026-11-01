// SPDX-License-Identifier: GPL-3.0-or-later
// Derived from SagerNet/sing-vmess and Polaris; see THIRD_PARTY_NOTICES.md.
package vless

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/protocol/vless/wire/encryption"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/logger"
)

func TestVisionEncryptionCarrierPreservesUnderlyingTransport(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	transportConn := &opaqueVisionTransport{Conn: client}
	encrypted := encryption.NewCommonConn(transportConn, false)
	vision, err := NewVisionConn(encrypted, encrypted, [16]byte{}, logger.NOP())
	if err != nil {
		t.Fatal(err)
	}
	if vision.netConn != transportConn {
		t.Fatalf("direct carrier = %T, want opaque transport", vision.netConn)
	}

	randomCarrier := encryption.NewXorConn(transportConn, nil, nil, 0, 0)
	randomEncrypted := encryption.NewCommonConn(randomCarrier, false)
	randomVision, err := NewVisionConn(randomEncrypted, randomEncrypted, [16]byte{}, logger.NOP())
	if err != nil {
		t.Fatal(err)
	}
	if randomVision.netConn != randomCarrier {
		t.Fatalf("random direct carrier = %T, want XorConn", randomVision.netConn)
	}
}

type opaqueVisionTransport struct{ net.Conn }

func TestVisionUnPaddingFragmentedHeaders(t *testing.T) {
	userUUID := [16]byte{1, 2, 3, 4}
	conn := &VisionConn{
		userUUID: userUUID, logger: logger.NOP(),
		withinPaddingBuffers: true, remainingContent: -1, remainingPadding: -1,
	}
	wire := append([]byte{}, userUUID[:]...)
	wire = append(wire, commandPaddingContinue, 0, 3, 0, 2)
	wire = append(wire, []byte("abc__")...)
	wire = append(wire, commandPaddingContinue, 0, 0, 0, 0)
	wire = append(wire, commandPaddingEnd, 0, 3, 0, 1)
	wire = append(wire, []byte("xyz_")...)

	var output []byte
	for _, value := range wire {
		for _, buffer := range conn.unPadding([]byte{value}) {
			output = append(output, buffer.Bytes()...)
			buffer.Release()
		}
	}
	if string(output) != "abcxyz" {
		t.Fatalf("unpadding output = %q", output)
	}
	if conn.currentCommand != commandPaddingEnd || conn.remainingContent != 0 || conn.remainingPadding != 0 {
		t.Fatalf("unexpected final padding state: command=%d content=%d padding=%d", conn.currentCommand, conn.remainingContent, conn.remainingPadding)
	}
}

func TestVisionFilterRejectsInvalidSessionIDLength(t *testing.T) {
	conn := &VisionConn{logger: logger.NOP(), numberOfPacketToFilter: 8, remainingServerHello: -1}
	serverHello := make([]byte, 79)
	serverHello[0], serverHello[1], serverHello[2] = 22, 3, 3
	serverHello[3], serverHello[4], serverHello[5] = 0, 74, 2
	serverHello[43] = 255
	conn.filterTLS([][]byte{serverHello})
	if conn.cipher != 0 {
		t.Fatalf("cipher = %x", conn.cipher)
	}
}

func TestVisionFilterRecognizesFragmentedTLS13ServerHello(t *testing.T) {
	conn := &VisionConn{logger: logger.NOP(), numberOfPacketToFilter: 8, remainingServerHello: -1}
	serverHello := make([]byte, 79)
	serverHello[0], serverHello[1], serverHello[2] = 22, 3, 3
	serverHello[3], serverHello[4], serverHello[5] = 0, 74, 2
	serverHello[43] = 0
	serverHello[44], serverHello[45] = 0x13, 0x01
	copy(serverHello[60:], tls13SupportedVersions)
	for _, value := range serverHello {
		conn.filterTLS([][]byte{{value}})
	}
	if !conn.isTLS12orAbove || !conn.enableXTLS || conn.cipher != 0x1301 {
		t.Fatalf("fragmented server hello state: tls12=%v xtls=%v cipher=%x", conn.isTLS12orAbove, conn.enableXTLS, conn.cipher)
	}
}

func TestVisionFilterConcurrentDirections(t *testing.T) {
	conn := &VisionConn{logger: logger.NOP(), numberOfPacketToFilter: 2000, remainingServerHello: -1}
	clientHello := []byte{22, 3, 1, 0, 2, 1, 0}
	serverHello := []byte{22, 3, 3, 0, 2, 2, 0}
	var waitGroup sync.WaitGroup
	for directionIndex, packet := range [][]byte{clientHello, serverHello} {
		directionIndex, packet := directionIndex, packet
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for range 1000 {
				if directionIndex == 0 {
					conn.filterTLSRead([][]byte{packet})
				} else {
					conn.filterTLS([][]byte{packet})
				}
			}
		}()
	}
	waitGroup.Wait()
}

func TestVisionReadConsumesEmptyFramesIteratively(t *testing.T) {
	userUUID := [16]byte{9, 8, 7, 6}
	fragments := make([][]byte, 0, 20002)
	first := append([]byte{}, userUUID[:]...)
	first = append(first, commandPaddingContinue, 0, 0, 0, 0)
	fragments = append(fragments, first)
	for index := 0; index < 20000; index++ {
		fragments = append(fragments, []byte{commandPaddingContinue, 0, 0, 0, 0})
	}
	fragments = append(fragments, []byte{commandPaddingEnd, 0, 1, 0, 0, 'x'})
	transport := &fragmentConn{fragments: fragments}
	conn := &VisionConn{
		Conn: transport, reader: bufio.NewChunkReader(transport, xrayChunkSize),
		netConn: transport, input: bytes.NewReader(nil), rawInput: new(bytes.Buffer),
		logger: logger.NOP(), userUUID: userUUID, withinPaddingBuffers: true,
		remainingContent: -1, remainingPadding: -1, remainingServerHello: -1,
	}
	var output [1]byte
	n, err := conn.Read(output[:])
	if err != nil || n != 1 || output[0] != 'x' {
		t.Fatalf("Read() = %d, %q, %v", n, output[:n], err)
	}
}

type fragmentConn struct {
	fragments [][]byte
	index     int
}

func (c *fragmentConn) Read(p []byte) (int, error) {
	if c.index >= len(c.fragments) {
		return 0, io.EOF
	}
	fragment := c.fragments[c.index]
	c.index++
	return copy(p, fragment), nil
}

func (*fragmentConn) Write(p []byte) (int, error)      { return len(p), nil }
func (*fragmentConn) Close() error                     { return nil }
func (*fragmentConn) LocalAddr() net.Addr              { return nil }
func (*fragmentConn) RemoteAddr() net.Addr             { return nil }
func (*fragmentConn) SetDeadline(time.Time) error      { return nil }
func (*fragmentConn) SetReadDeadline(time.Time) error  { return nil }
func (*fragmentConn) SetWriteDeadline(time.Time) error { return nil }
