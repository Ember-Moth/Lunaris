// SPDX-License-Identifier: GPL-3.0-or-later
// Derived from SagerNet/sing-vmess and Polaris; see THIRD_PARTY_NOTICES.md.
package vless

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"

	vmess "github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
)

func TestClientPacketConnFirstWritePacketHasSingleLengthPrefix(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	destination := M.ParseSocksaddr("192.0.2.53:53")
	packetConn := &PacketConn{Conn: client, destination: destination}
	payload := []byte("first-packet")
	writeDone := make(chan error, 1)
	go func() {
		buffer := buf.NewSize(len(payload))
		_, _ = buffer.Write(payload)
		writeDone <- packetConn.WritePacket(buffer, destination)
	}()
	request, err := ReadRequest(server)
	if err != nil {
		t.Fatal(err)
	}
	if request.Command != vmess.CommandUDP || request.Destination != destination {
		t.Fatalf("request = %+v", request)
	}
	var packetLength uint16
	if err = binary.Read(server, binary.BigEndian, &packetLength); err != nil {
		t.Fatal(err)
	}
	if int(packetLength) != len(payload) {
		t.Fatalf("packet length = %d, want %d", packetLength, len(payload))
	}
	received := make([]byte, packetLength)
	if _, err = io.ReadFull(server, received); err != nil {
		t.Fatal(err)
	}
	if string(received) != string(payload) {
		t.Fatalf("payload = %q", received)
	}
	if err = <-writeDone; err != nil {
		t.Fatal(err)
	}
}

func TestClientPacketConnShortReadKeepsPacketAlignment(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	packetConn := &PacketConn{Conn: client}
	writeDone := make(chan error, 1)
	go func() {
		wire := []byte{Version, 0}
		for _, payload := range [][]byte{[]byte("oversized"), []byte("ok")} {
			wire = binary.BigEndian.AppendUint16(wire, uint16(len(payload)))
			wire = append(wire, payload...)
		}
		_, err := server.Write(wire)
		writeDone <- err
	}()
	if _, err := packetConn.Read(make([]byte, 2)); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("short read error = %v", err)
	}
	output := make([]byte, 2)
	n, err := packetConn.Read(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(output[:n]) != "ok" {
		t.Fatalf("second packet = %q", output[:n])
	}
	if err = <-writeDone; err != nil {
		t.Fatal(err)
	}
}

func TestServerPacketConnWriteToReservesResponseHeader(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	packetConn := &serverPacketConn{ExtendedConn: bufio.NewExtendedConn(client)}
	writeDone := make(chan error, 1)
	go func() {
		_, err := packetConn.WriteTo([]byte("ok"), &net.UDPAddr{IP: net.IPv4(192, 0, 2, 53), Port: 53})
		writeDone <- err
	}()
	var wire [6]byte
	if _, err := io.ReadFull(server, wire[:]); err != nil {
		t.Fatal(err)
	}
	if wire != [6]byte{Version, 0, 0, 2, 'o', 'k'} {
		t.Fatalf("response wire = %v", wire)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
}

func TestPacketConnsRejectOversizedDatagrams(t *testing.T) {
	payload := make([]byte, 1<<16)
	client := &PacketConn{}
	if _, err := client.Write(payload); err == nil {
		t.Fatal("client Write accepted oversized datagram")
	}
	clientBuffer := buf.NewSize(len(payload))
	_, _ = clientBuffer.Write(payload)
	if err := client.WritePacket(clientBuffer, M.Socksaddr{}); err == nil {
		t.Fatal("client WritePacket accepted oversized datagram")
	}
	serverBuffer := buf.NewSize(len(payload))
	_, _ = serverBuffer.Write(payload)
	server := &serverPacketConn{}
	if err := server.WritePacket(serverBuffer, M.Socksaddr{}); err == nil {
		t.Fatal("server WritePacket accepted oversized datagram")
	}
}
