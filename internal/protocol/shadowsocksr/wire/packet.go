// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package shadowsocksr

import (
	"sync"

	"github.com/sagernet/sing/common/buf"
)

type PacketCodec struct {
	server *Server
	pool   sync.Pool
}

type packetState struct {
	iv      []byte
	scratch []byte
}

func (s *Server) NewPacketCodec() (*PacketCodec, error) {
	codec := &PacketCodec{server: s}
	codec.pool.Put(&packetState{iv: make([]byte, s.cipher.IVLen())})
	return codec, nil
}

func (c *PacketCodec) acquire() *packetState {
	if value := c.pool.Get(); value != nil {
		return value.(*packetState)
	}
	return &packetState{iv: make([]byte, c.server.cipher.IVLen())}
}

func (c *PacketCodec) Decode(buffer *buf.Buffer) ([4]byte, error) {
	var zero [4]byte
	data, iv, err := c.server.cipher.OpenPacket(buffer.Bytes())
	if err != nil {
		return zero, err
	}
	data, userID, err := c.server.protocol.DecodePacket(nil, data, iv)
	if err != nil {
		return zero, err
	}
	buffer.Reset()
	_, err = buffer.Write(data)
	return userID, err
}

func (c *PacketCodec) Encode(buffer *buf.Buffer, userID [4]byte) (*buf.Buffer, error) {
	state := c.acquire()
	defer c.pool.Put(state)
	iv, err := c.server.cipher.RandomIV(state.iv)
	if err != nil {
		return nil, err
	}
	state.scratch, err = c.server.protocol.EncodePacket(state.scratch[:0], buffer.Bytes(), userID, iv)
	if err != nil {
		return nil, err
	}
	required := c.server.cipher.PacketOverhead() + len(state.scratch)
	if required <= buffer.RawCap() {
		buffer.Reset()
		output, sealErr := c.server.cipher.SealPacket(buffer.FreeBytes()[:0], state.scratch, iv)
		if sealErr != nil {
			return nil, sealErr
		}
		buffer.Truncate(len(output))
		return buffer, nil
	}
	encoded := buf.NewSize(required)
	output, err := c.server.cipher.SealPacket(encoded.FreeBytes()[:0], state.scratch, iv)
	if err != nil {
		encoded.Release()
		return nil, err
	}
	encoded.Truncate(len(output))
	return encoded, nil
}
