// SPDX-License-Identifier: GPL-3.0-only
package naive

import (
	"bytes"
	"io"
	"net"
	"testing"
)

type memoryConn struct {
	net.Conn
	reader io.Reader
	writer io.Writer
}

func (c memoryConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c memoryConn) Write(p []byte) (int, error) { return c.writer.Write(p) }

type oneByteReader struct{ io.Reader }

func (r oneByteReader) Read(p []byte) (int, error) { return r.Reader.Read(p[:min(len(p), 1)]) }
func TestPaddingFragmentationAndFinalPadding(t *testing.T) {
	var wire []byte
	for i := 0; i < 8; i++ {
		if i%2 == 0 {
			wire = append(wire, 0, 0, 2, 0xa5, 0xa5)
		} else {
			wire = append(wire, 0, 1, 2, 'x', 0xa5, 0xa5)
		}
	}
	wire = append(wire, []byte("unframed")...)
	c := &paddingConn{Conn: memoryConn{reader: oneByteReader{bytes.NewReader(wire)}}}
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "xxxxunframed" {
		t.Fatalf("padding escaped or data changed: %x %v", got, err)
	}
}
func TestPaddingLargeWriteAndTransition(t *testing.T) {
	var wire bytes.Buffer
	c := &paddingConn{Conn: memoryConn{writer: &wire}}
	payload := bytes.Repeat([]byte{'x'}, 65536)
	if n, err := c.Write(payload); err != nil || n != len(payload) {
		t.Fatal(n, err)
	}
	for i := 2; i < 8; i++ {
		if _, err := c.Write([]byte{'x'}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.Write([]byte("plain")); err != nil {
		t.Fatal(err)
	}
	// Parse the documented format independently, including the eight-frame boundary.
	got := new(bytes.Buffer)
	for i := 0; i < 8; i++ {
		h := wire.Next(3)
		if len(h) != 3 {
			t.Fatal("missing frame")
		}
		size := int(h[0])<<8 | int(h[1])
		if i == 0 && size != 65535 {
			t.Fatal("large write did not split")
		}
		got.Write(wire.Next(size))
		if len(wire.Next(int(h[2]))) != int(h[2]) {
			t.Fatal("missing padding")
		}
	}
	if !bytes.Equal(got.Bytes(), bytes.Repeat([]byte{'x'}, 65542)) || wire.String() != "plain" {
		t.Fatal("incorrect framing transition")
	}
}
