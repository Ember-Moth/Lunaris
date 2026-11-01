// SPDX-License-Identifier: GPL-3.0-only
package vless

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	vmess "github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

func TestXUDPPacketDeadlineInterruptsRead(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	c := &serverMuxPacketConn{pipe: a}
	if err := c.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.ReadFrom(make([]byte, 16)); err == nil {
		t.Fatal("idle XUDP stream remained open")
	}
}

func TestMuxBufferedAndPacketWritesDoNotInterleave(t *testing.T) {
	session := newMuxTestSession(nil, 4)
	tcp := &serverMuxConn{sessionID: 1, session: session}
	udp := &serverMuxPacketConn{sessionID: 2, session: session}
	dst := M.ParseSocksaddr("127.0.0.1:53")
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Go(func() {
			b := buf.NewSize(1100)
			b.Write(bytes.Repeat([]byte{byte(i)}, 1100))
			if err := tcp.WriteBuffer(b); err != nil {
				t.Error(err)
			}
		})
		wg.Go(func() {
			b := buf.NewSize(1700)
			b.Write(bytes.Repeat([]byte{byte(i)}, 1700))
			if err := udp.WritePacket(b, dst); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	reader := bytes.NewReader(session.conn.(*muxTestConn).output.Bytes())
	for range 64 {
		var length, id uint16
		if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
			t.Fatal(err)
		}
		meta := make([]byte, length)
		if _, err := io.ReadFull(reader, meta); err != nil {
			t.Fatal(err)
		}
		id = binary.BigEndian.Uint16(meta)
		if meta[2] != vmess.StatusKeep || meta[3] != vmess.OptionData || (id != 1 && id != 2) {
			t.Fatal("corrupt frame metadata", meta)
		}
		if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
			t.Fatal(err)
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(reader, payload); err != nil {
			t.Fatal(err)
		}
		if len(payload) != (map[uint16]int{1: 1100, 2: 1700})[id] || !bytes.Equal(payload, bytes.Repeat(payload[:1], len(payload))) {
			t.Fatal("interleaved frame data")
		}
	}
	if reader.Len() != 0 {
		t.Fatal("trailing frames")
	}
}
