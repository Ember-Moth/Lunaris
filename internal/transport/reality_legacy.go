// SPDX-License-Identifier: GPL-3.0-only
package transport

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"

	legacy "github.com/metacubex/utls"
	N "github.com/sagernet/sing/common/network"
)

// selectRealityBackend observes a bounded, possibly fragmented ClientHello and
// replays every original byte. It never rewrites TLS transcript data and never
// retries a failed authenticated handshake against another implementation.
func selectRealityBackend(c net.Conn) (net.Conn, bool, error) {
	var records, hello bytes.Buffer
	replay := func(compat bool) (net.Conn, bool, error) {
		return &helloReplay{Conn: c, reader: io.MultiReader(bytes.NewReader(records.Bytes()), c)}, compat, nil
	}
	for range 64 {
		var header [5]byte
		n, err := io.ReadFull(c, header[:])
		records.Write(header[:n])
		if err != nil {
			return nil, false, err
		}
		size := int(binary.BigEndian.Uint16(header[3:]))
		if header[0] != 22 || size == 0 || size > 18432 {
			return replay(false)
		}
		payload := make([]byte, size)
		n, err = io.ReadFull(c, payload)
		records.Write(payload[:n])
		if err != nil {
			return nil, false, err
		}
		hello.Write(payload)
		data := hello.Bytes()
		if len(data) < 4 {
			continue
		}
		if data[0] != 1 {
			return replay(false)
		}
		length := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
		if length > 65536 {
			return replay(false)
		}
		if len(data) < length+4 {
			continue
		}
		parsed := legacy.UnmarshalClientHello(data[:length+4])
		if parsed == nil {
			return replay(false)
		}
		x25519 := false
		for _, share := range parsed.KeyShares {
			// Keep every advertised modern share, including malformed ones, on the
			// strict upstream path. Only genuine old X25519-only hellos use compat.
			if share.Group == legacy.X25519MLKEM768 {
				return replay(false)
			}
			if share.Group == legacy.X25519 && len(share.Data) == 32 {
				x25519 = true
			}
		}
		return replay(x25519)
	}
	return replay(false)
}

type helloReplay struct {
	net.Conn
	reader io.Reader
}

func (c *helloReplay) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (c *helloReplay) CloseWrite() error          { return N.CloseWrite(c.Conn) }
func (c *helloReplay) CloseRead() error           { return N.CloseRead(c.Conn) }

// The compatible backend follows sing-box's full-close behavior on CloseWrite.
// Its REALITY connection does not provide a reliable independent half-close.
type legacyRealityConn struct{ *legacy.Conn }

func (c *legacyRealityConn) CloseWrite() error { return c.Close() }
