// SPDX-License-Identifier: GPL-3.0-only
// Derived and modified from github.com/MetaCubeX/mihomo transport/simple-obfs.

package obfs

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"
)

const tlsServerHelloSize = 107

var tlsServerHelloPool = sync.Pool{New: func() any { return new([tlsServerHelloSize]byte) }}

func makeServerHelloHeader(header *[tlsServerHelloSize]byte, payloadLength int) error {
	header[0], header[1], header[2], header[3], header[4] = 0x16, 0x03, 0x01, 0x00, 0x5b
	copy(header[5:11], []byte{0x02, 0x00, 0x00, 0x57, 0x03, 0x03})
	binary.BigEndian.PutUint32(header[11:15], uint32(time.Now().Unix()))
	if _, err := rand.Read(header[15:43]); err != nil {
		return err
	}
	header[43] = 32
	if _, err := rand.Read(header[44:76]); err != nil {
		return err
	}
	copy(
		header[76:96],
		[]byte{
			0xcc,
			0xa8,
			0x00,
			0x00,
			0x00,
			0xff,
			0x01,
			0x00,
			0x01,
			0x00,
			0x00,
			0x17,
			0x00,
			0x00,
			0x00,
			0x0b,
			0x00,
			0x02,
			0x01,
			0x00,
		},
	)
	copy(header[96:105], []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x16, 0x03, 0x03})
	binary.BigEndian.PutUint16(header[105:107], uint16(payloadLength))
	return nil
}

func writePrefixedPayload(writer io.Writer, prefix, payload []byte) (int, error) {
	var vector [2][]byte
	return writePrefixedPayloadWithVector(writer, prefix, payload, &vector)
}

func writePrefixedPayloadWithVector(writer io.Writer, prefix, payload []byte, vector *[2][]byte) (int, error) {
	vector[0], vector[1] = prefix, payload
	buffers := net.Buffers(vector[:])
	written, err := buffers.WriteTo(writer)
	vector[0], vector[1] = nil, nil
	payloadWritten := max(int(written)-len(prefix), 0)
	payloadWritten = min(payloadWritten, len(payload))
	if err == nil && payloadWritten != len(payload) {
		err = io.ErrShortWrite
	}
	return payloadWritten, err
}
