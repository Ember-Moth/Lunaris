// SPDX-License-Identifier: GPL-3.0-only
package vless

import (
	"bytes"
	"io"
	"net"
	"reflect"
	"testing"
	"unsafe"

	"github.com/sagernet/sing/common/logger"
)

type pointerRecordConn struct {
	net.Conn
	input    bytes.Reader
	rawInput *bytes.Buffer
	wire     *bytes.Reader
}

func (c *pointerRecordConn) Read(p []byte) (int, error) { return c.wire.Read(p) }
func (c *pointerRecordConn) VisionTLSConnection() (net.Conn, reflect.Type, unsafe.Pointer) {
	return c.Conn, reflect.TypeOf(*c), unsafe.Pointer(c)
}

func TestVisionReadsCurrentRecordBufferAfterDirectSwitch(t *testing.T) {
	for _, buffered := range []bool{false, true} {
		raw, peer := net.Pipe()
		defer raw.Close()
		defer peer.Close()
		uuid := [16]byte{1, 2, 3}
		frame := append(append([]byte{}, uuid[:]...), commandPaddingDirect, 0, 1, 0, 0, 'a')
		carrier := &pointerRecordConn{Conn: raw, rawInput: bytes.NewBufferString("stale"), wire: bytes.NewReader(frame)}
		conn, err := NewVisionConn(carrier, carrier, uuid, logger.NOP())
		if err != nil {
			t.Fatal(err)
		}
		want := "a"
		if buffered {
			carrier.input.Reset([]byte("b"))
			carrier.rawInput = bytes.NewBufferString("c")
			want = "abc"
		} else {
			carrier.rawInput = nil
		}
		got := make([]byte, len(want))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatal(err)
		}
		if string(got) != want || !conn.directRead {
			t.Fatalf("buffer=%q, direct=%v", got, conn.directRead)
		}
	}
}

func TestVisionRejectsOpaqueCarrier(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if _, err := NewVisionConn(a, a, [16]byte{}, logger.NOP()); err == nil {
		t.Fatal("opaque non-record carrier accepted")
	}
}
