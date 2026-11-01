// SPDX-License-Identifier: GPL-3.0-or-later
// Derived from SagerNet/sing-vmess and Polaris; see THIRD_PARTY_NOTICES.md.
package vless

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
)

func TestServerPacketConnWriteBatch(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	conn := &serverPacketConn{ExtendedConn: bufio.NewExtendedConn(client)}
	payloads := [][]byte{[]byte("first"), []byte("second")}
	buffers := make([]*buf.Buffer, len(payloads))
	for index, payload := range payloads {
		buffers[index] = buf.NewSize(2 + len(payload))
		buffers[index].Resize(2, 0)
		_, _ = buffers[index].Write(payload)
	}
	destinations := []M.Socksaddr{M.ParseSocksaddr("1.1.1.1:53"), M.ParseSocksaddr("8.8.8.8:53")}
	writeDone := make(chan error, 1)
	go func() { writeDone <- conn.WritePacketBatch(buffers, destinations) }()
	var response [2]byte
	if _, err := io.ReadFull(server, response[:]); err != nil {
		t.Fatal(err)
	}
	if response != [2]byte{Version, 0} {
		t.Fatalf("response header=%v", response)
	}
	for index := range payloads {
		var length uint16
		if err := binary.Read(server, binary.BigEndian, &length); err != nil {
			t.Fatal(err)
		}
		payload := make([]byte, int(length))
		if _, err := io.ReadFull(server, payload); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(payload, payloads[index]) {
			t.Fatalf("payload=%q, want %q", payload, payloads[index])
		}
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
}
