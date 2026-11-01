// Copyright 2015-2015 breakwa11
// SPDX-License-Identifier: Apache-2.0
//
// Frame helpers shared by the legacy protocols derive from
// shadowsocksr-backup/shadowsocksr shadowsocks/obfsplugin/verify.py and
// auth.py at db6629a1307ed38eb507bd926ad1503e90bc4eb1.
// Modified by Polaris contributors, 2026-07-31 to 2026-08-28: translated to
// Go and later rewritten for this module; see MODIFICATIONS.md.

package protocol

import (
	"crypto/rand"
	"encoding/binary"
	"hash/crc32"
	"io"
)

const (
	legacyFrameLimit = 8192
	legacyUnitLength = 8100
)

func packCRCFrames(dst, payload []byte) ([]byte, error) {
	for len(payload) > 0 {
		length := min(len(payload), legacyUnitLength)
		var err error
		dst, err = packCRCFrame(dst, payload[:length])
		if err != nil {
			return nil, err
		}
		payload = payload[length:]
	}
	return dst, nil
}

func packCRCFrame(dst, payload []byte) ([]byte, error) {
	randomLength, err := randomModulo(16)
	if err != nil {
		return nil, err
	}
	frameLength := 2 + 1 + randomLength + len(payload) + 4
	start := len(dst)
	dst = append(dst, make([]byte, frameLength)...)
	frame := dst[start:]
	binary.BigEndian.PutUint16(frame[:2], uint16(frameLength))
	frame[2] = byte(randomLength + 1)
	if _, err = io.ReadFull(rand.Reader, frame[3:3+randomLength]); err != nil {
		return nil, err
	}
	copy(frame[3+randomLength:], payload)
	checksumAt := frameLength - 4
	binary.LittleEndian.PutUint32(frame[checksumAt:], ^crc32.ChecksumIEEE(frame[:checksumAt]))
	return dst, nil
}

func randomModulo(modulus int) (int, error) {
	if modulus <= 1 {
		return 0, nil
	}
	var raw [2]byte
	if _, err := io.ReadFull(rand.Reader, raw[:]); err != nil {
		return 0, err
	}
	return int(binary.BigEndian.Uint16(raw[:])) % modulus, nil
}

func legacyPayloadPosition(frame []byte, offset, trailer int) (int, bool) {
	if offset < 0 || offset >= len(frame)-trailer {
		return 0, false
	}
	padding := int(frame[offset])
	position := offset + padding
	if padding == 0 || position < offset+1 || position > len(frame)-trailer {
		return 0, false
	}
	return position, true
}

func socksHeaderLength(data []byte) (int, bool) {
	if len(data) == 0 {
		return 0, false
	}
	switch data[0] & 7 {
	case 1:
		return 7, len(data) >= 7
	case 4:
		return 19, len(data) >= 19
	case 3:
		if len(data) < 2 {
			return 0, false
		}
		length := 4 + int(data[1])
		return length, len(data) >= length
	default:
		return 0, false
	}
}
