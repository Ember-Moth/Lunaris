// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package shadowsocksr

import (
	"crypto/cipher"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"

	ssrcipher "github.com/Ember-Moth/Lunaris/internal/protocol/shadowsocksr/wire/cipher"
	ssrobfs "github.com/Ember-Moth/Lunaris/internal/protocol/shadowsocksr/wire/obfs"
	ssrprotocol "github.com/Ember-Moth/Lunaris/internal/protocol/shadowsocksr/wire/protocol"
)

const serverStreamMTU = 8 * 1024

type ServerConn struct {
	net.Conn
	server             *Server
	protocol           ssrprotocol.Stream
	obfs               ssrobfs.Stream
	readStream         cipher.Stream
	writeStream        cipher.Stream
	readAEAD           *ssrcipher.AEADStream
	writeAEAD          *ssrcipher.AEADStream
	readIV             []byte
	writeIV            []byte
	decoded            []byte
	readCipherScratch  []byte
	writeCipherScratch []byte
	writeScratch       []byte
	wireScratch        []byte
	ivSent             bool
	replayChecked      bool
	readMu             sync.Mutex
	codecMu            sync.Mutex
	writeMu            sync.Mutex
	closeOnce          sync.Once
	closed             atomic.Bool
	closeErr           error
}

func (s *Server) WrapConn(conn net.Conn) (*ServerConn, error) {
	writeIV, err := s.cipher.RandomIV(nil)
	if err != nil {
		return nil, err
	}
	var writeStream cipher.Stream
	var writeAEAD *ssrcipher.AEADStream
	if s.cipher.IsAEAD() {
		writeAEAD, err = s.cipher.NewAEADStream(writeIV)
	} else {
		writeStream, err = s.cipher.NewEncryptStream(writeIV)
	}
	if err != nil {
		return nil, err
	}
	return &ServerConn{
		Conn:        conn,
		server:      s,
		protocol:    s.protocol.NewStream(writeIV),
		obfs:        s.obfs.NewStream(),
		writeStream: writeStream,
		writeAEAD:   writeAEAD,
		readIV:      make([]byte, 0, s.cipher.IVLen()),
		writeIV:     writeIV,
	}, nil
}

func (c *ServerConn) UserID() ([4]byte, bool) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	c.codecMu.Lock()
	defer c.codecMu.Unlock()
	return c.protocol.UserID()
}

func (c *ServerConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	for {
		if len(c.decoded) > 0 {
			n := copy(p, c.decoded)
			c.decoded = c.decoded[n:]
			return n, nil
		}
		data, borrowed, err := c.readFrame(nil)
		if len(data) == 0 {
			if err != nil {
				return 0, err
			}
			continue
		}
		n := copy(p, data)
		if n < len(data) {
			if borrowed {
				c.decoded = slices.Clone(data[n:])
			} else {
				c.decoded = data[n:]
			}
		}
		return n, err
	}
}

func (c *ServerConn) readFrame(dst []byte) (data []byte, borrowed bool, err error) {
	raw := buf.NewSize(serverStreamMTU)
	defer raw.Release()
	n, readErr := raw.ReadOnceFrom(c.Conn)
	if n == 0 {
		return nil, false, readErr
	}
	c.codecMu.Lock()
	input, decrypt, obfsReply, decodeErr := c.obfs.Decode(raw.Bytes())
	c.codecMu.Unlock()
	if decodeErr != nil {
		return nil, false, decodeErr
	}
	if obfsReply {
		if err = c.writeObfsReply(); err != nil {
			return nil, false, err
		}
	}
	if !decrypt || len(input) == 0 {
		return nil, false, readErr
	}
	if c.readStream == nil && c.readAEAD == nil {
		needed := c.server.cipher.IVLen() - len(c.readIV)
		consumed := min(needed, len(input))
		c.readIV = append(c.readIV, input[:consumed]...)
		input = input[consumed:]
		if len(c.readIV) != c.server.cipher.IVLen() {
			return nil, false, readErr
		}
		if c.server.cipher.IsAEAD() {
			c.readAEAD, err = c.server.cipher.NewAEADStream(c.readIV)
		} else {
			c.readStream, err = c.server.cipher.NewDecryptStream(c.readIV)
		}
		if err != nil {
			return nil, false, err
		}
		c.codecMu.Lock()
		c.protocol.SetReadIV(c.readIV)
		c.codecMu.Unlock()
	}
	if len(input) == 0 {
		return nil, false, readErr
	}
	if c.readAEAD != nil {
		c.readCipherScratch, err = c.readAEAD.Open(c.readCipherScratch[:0], input)
		if err != nil {
			return nil, false, err
		}
		if c.readAEAD.Authenticated() && !c.replayChecked {
			if !c.server.checkCipherReplay(c.readIV) {
				return nil, false, ssrcipher.ErrReplay
			}
			c.replayChecked = true
		}
		input = c.readCipherScratch
		if len(input) == 0 {
			if readErr != nil && c.readAEAD.Pending() {
				return nil, false, io.ErrUnexpectedEOF
			}
			return nil, false, readErr
		}
	} else {
		c.readStream.XORKeyStream(input, input)
	}
	c.codecMu.Lock()
	data, borrowed, reply, err := c.protocol.Decode(dst, input)
	// readFrame releases its receive buffer before the caller copies the result.
	// Retain bytes borrowed from that buffer across the ownership boundary.
	if borrowed {
		data = slices.Clone(data)
		borrowed = false
	}
	c.codecMu.Unlock()
	if err == nil && reply {
		err = c.writeReply(nil)
	}
	if err == nil {
		err = readErr
	}
	return data, borrowed, err
}

func (c *ServerConn) writeObfsReply() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed.Load() {
		return net.ErrClosed
	}
	c.codecMu.Lock()
	wire, err := c.obfs.Encode(c.wireScratch[:0], nil)
	c.codecMu.Unlock()
	if err != nil {
		return err
	}
	c.wireScratch = wire
	return writeAll(c.Conn, wire)
}

func (c *ServerConn) ReadBuffer(buffer *buf.Buffer) error {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.closed.Load() {
		return net.ErrClosed
	}
	for {
		if len(c.decoded) > 0 {
			n := copy(buffer.FreeBytes(), c.decoded)
			buffer.Truncate(buffer.Len() + n)
			c.decoded = c.decoded[n:]
			return nil
		}
		if buffer.FreeLen() == 0 {
			return io.ErrShortBuffer
		}
		data, borrowed, err := c.readFrame(buffer.FreeBytes()[:0])
		if len(data) == 0 {
			if err != nil {
				return err
			}
			continue
		}
		n := copy(buffer.FreeBytes(), data)
		buffer.Truncate(buffer.Len() + n)
		if n < len(data) {
			if borrowed {
				c.decoded = slices.Clone(data[n:])
			} else {
				c.decoded = data[n:]
			}
		}
		return err
	}
}

func (c *ServerConn) Write(p []byte) (int, error) {
	if err := c.writeReply(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *ServerConn) writeReply(payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed.Load() {
		return net.ErrClosed
	}
	wire, err := c.encodeReply(payload)
	if err != nil {
		return err
	}
	return writeAll(c.Conn, wire)
}

func (c *ServerConn) encodeReply(payload []byte) ([]byte, error) {
	c.codecMu.Lock()
	defer c.codecMu.Unlock()
	var err error
	var cipherOutput []byte
	if c.writeAEAD != nil {
		c.writeScratch, err = c.protocol.Encode(c.writeScratch[:0], payload)
		if err != nil {
			return nil, err
		}
		c.writeCipherScratch = c.writeCipherScratch[:0]
		if !c.ivSent {
			c.writeCipherScratch = append(c.writeCipherScratch, c.writeIV...)
		}
		c.writeCipherScratch, err = c.writeAEAD.Seal(c.writeCipherScratch, c.writeScratch)
		if err != nil {
			return nil, err
		}
		cipherOutput = c.writeCipherScratch
	} else {
		prefix := 0
		if !c.ivSent {
			prefix = len(c.writeIV)
		}
		c.writeScratch = c.writeScratch[:0]
		c.writeScratch = append(c.writeScratch, c.writeIV[:prefix]...)
		c.writeScratch, err = c.protocol.Encode(c.writeScratch, payload)
		if err != nil {
			return nil, err
		}
		c.writeStream.XORKeyStream(c.writeScratch[prefix:], c.writeScratch[prefix:])
		cipherOutput = c.writeScratch
	}
	c.ivSent = true
	wire, err := c.obfs.Encode(c.wireScratch[:0], cipherOutput)
	if err != nil {
		return nil, err
	}
	c.wireScratch = wire
	return wire, nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func (c *ServerConn) WriteBuffer(buffer *buf.Buffer) error {
	defer buffer.Release()
	_, err := c.Write(buffer.Bytes())
	return err
}

func (c *ServerConn) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		// Closing the raw transport first interrupts in-flight I/O. Cleanup then
		// follows the Read -> Write lock order used by the feedback path.
		c.closeErr = c.Conn.Close()
		c.readMu.Lock()
		c.writeMu.Lock()
		c.protocol.Close()
		c.obfs.Close()
		if c.readAEAD != nil {
			c.readAEAD.Close()
		}
		if c.writeAEAD != nil {
			c.writeAEAD.Close()
		}
		c.decoded = nil
		c.readCipherScratch = nil
		c.writeCipherScratch = nil
		c.writeScratch = nil
		c.wireScratch = nil
		c.writeMu.Unlock()
		c.readMu.Unlock()
	})
	return c.closeErr
}

func (c *ServerConn) Upstream() any { return c.Conn }

func (*ServerConn) ReaderMTU() int { return serverStreamMTU }

func (*ServerConn) WriterMTU() int { return serverStreamMTU }

var _ N.ExtendedConn = (*ServerConn)(nil)
