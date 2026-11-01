// SPDX-License-Identifier: GPL-3.0-only
package naive

import (
	"encoding/binary"
	"io"
	"math/rand/v2"
	"net"
	"sync"
)

// Naive variant-1 frames the first eight writes in each direction as
// uint16(payload length), uint8(padding length), payload, padding. Later bytes
// are unframed. Keep partial reads, empty frames and the final padding intact.
type paddingConn struct {
	net.Conn
	readMu, writeMu                             sync.Mutex
	readFrames, writeFrames, remaining, padding int
}

func (c *paddingConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if c.remaining > 0 {
			n, err := c.Conn.Read(p[:min(len(p), c.remaining)])
			c.remaining -= n
			return n, err
		}
		if c.padding > 0 {
			_, err := io.CopyN(io.Discard, c.Conn, int64(c.padding))
			if err != nil {
				return 0, err
			}
			c.padding = 0
		}
		if c.readFrames >= 8 {
			return c.Conn.Read(p)
		}
		var h [3]byte
		if _, err := io.ReadFull(c.Conn, h[:]); err != nil {
			return 0, err
		}
		c.readFrames++
		c.remaining = int(binary.BigEndian.Uint16(h[:2]))
		c.padding = int(h[2])
	}
}
func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		p = p[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
func (c *paddingConn) Write(p []byte) (n int, err error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	for len(p) > 0 {
		if c.writeFrames >= 8 {
			m, e := c.Conn.Write(p)
			return n + m, e
		}
		size := min(len(p), 65535)
		padding := rand.IntN(256)
		frame := make([]byte, 3+size+padding)
		binary.BigEndian.PutUint16(frame[:2], uint16(size))
		frame[2] = byte(padding)
		copy(frame[3:], p[:size])
		if err = writeAll(c.Conn, frame); err != nil {
			return n, err
		}
		c.writeFrames++
		n += size
		p = p[size:]
	}
	return
}
func paddingHeader() string {
	p := make([]byte, 30+rand.IntN(32))
	for i := range p {
		p[i] = "!#$()+<>?@[]^`{}~"[rand.IntN(17)]
	}
	return string(p)
}
