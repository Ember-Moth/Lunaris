// Copyright 2015-2015 breakwa11
// SPDX-License-Identifier: Apache-2.0
//
// auth_sha1, auth_sha1_v2 and auth_sha1_v4 derive from
// shadowsocksr-backup/shadowsocksr shadowsocks/obfsplugin/auth.py at
// db6629a1307ed38eb507bd926ad1503e90bc4eb1; auth_simple follows auth.py at
// a440a726f6d3a25fe2eeac94786580f462a314a7.
// Modified by Polaris contributors, 2026-07-31 to 2026-08-28: translated to
// Go and later rewritten for this module; see MODIFICATIONS.md.

package protocol

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"hash/adler32"
	"hash/crc32"
	"io"
	"sync/atomic"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/protocol/shadowsocksr/wire/replay"
)

type legacyAuthKind uint8

const (
	authSimple legacyAuthKind = iota
	authSHA1
	authSHA1V2
	authSHA1V4
)

type legacyAuthDefinition struct {
	name      string
	kind      legacyAuthKind
	userID    [4]byte
	serverKey []byte
	now       func() time.Time
	replay    *replay.Cache
}

func newLegacyAuthDefinition(config Config) *legacyAuthDefinition {
	kind := authSimple
	switch config.Name {
	case "auth_sha1":
		kind = authSHA1
	case "auth_sha1_v2":
		kind = authSHA1V2
	case "auth_sha1_v4":
		kind = authSHA1V4
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &legacyAuthDefinition{name: config.Name, kind: kind, userID: config.SingleUserID,
		serverKey: config.ServerKey, now: now, replay: config.Replay}
}

func (*legacyAuthDefinition) Metadata() Metadata { return Metadata{SingleUser: true} }

func (d *legacyAuthDefinition) Overhead() int {
	if d.kind == authSimple {
		return 0
	}
	return 7
}

func (d *legacyAuthDefinition) NewStream(_ []byte) Stream {
	return &legacyAuthStream{definition: d}
}

func (d *legacyAuthDefinition) DecodePacket(_ []byte, packet, _ []byte) ([]byte, [4]byte, error) {
	return packet, d.userID, nil
}

func (*legacyAuthDefinition) EncodePacket(dst, payload []byte, _ [4]byte, _ []byte) ([]byte, error) {
	return append(dst, payload...), nil
}

type legacyAuthStream struct {
	definition     *legacyAuthDefinition
	readIV         []byte
	receive        receiveBuffer
	receivedHeader bool
	authenticated  bool
	feedback       atomic.Bool
}

func (s *legacyAuthStream) SetReadIV(iv []byte) { s.readIV = append(s.readIV[:0], iv...) }

func (s *legacyAuthStream) Decode(dst, input []byte) (result []byte, borrowed, reply bool, err error) {
	received, inputBorrowed := s.receive.feed(input)
	defer func() { s.receive.commit(received, inputBorrowed) }()
	result = dst
	if !s.receivedHeader {
		payload, consumed, complete, decodeErr := s.decodeHeader(received)
		if decodeErr != nil {
			return nil, false, false, decodeErr
		}
		if !complete {
			return result, false, false, nil
		}
		result = append(result, payload...)
		received = received[consumed:]
		s.receivedHeader = true
		s.authenticated = true
		reply = s.supportsFeedback()
	}
	decoded, remaining, frameFeedback, decodeErr := s.decodeFrames(result, received)
	if decodeErr != nil {
		return nil, false, false, decodeErr
	}
	result = decoded
	received = remaining
	reply = reply || frameFeedback
	if reply {
		s.feedback.Store(true)
	}
	return result, false, reply, nil
}

func (s *legacyAuthStream) Encode(dst, payload []byte) ([]byte, error) {
	if len(payload) == 0 {
		if !s.supportsFeedback() || !s.feedback.Swap(false) {
			return dst, nil
		}
		return appendLegacyDataFrame(dst, nil, s.definition.kind)
	}
	s.feedback.Store(false)
	for len(payload) > 0 {
		length := min(len(payload), legacyUnitLength)
		var err error
		dst, err = appendLegacyDataFrame(dst, payload[:length], s.definition.kind)
		if err != nil {
			return nil, err
		}
		payload = payload[length:]
	}
	return dst, nil
}

func (s *legacyAuthStream) UserID() ([4]byte, bool) {
	return s.definition.userID, s.authenticated
}

func (s *legacyAuthStream) Close() { s.receive.release() }

func (s *legacyAuthStream) supportsFeedback() bool {
	return s.definition.kind == authSHA1V2 || s.definition.kind == authSHA1V4
}

func (s *legacyAuthStream) decodeHeader(data []byte) ([]byte, int, bool, error) {
	switch s.definition.kind {
	case authSimple:
		return s.decodeSimpleHeader(data)
	case authSHA1V4:
		return s.decodeV4Header(data)
	default:
		return s.decodeSHA1Header(data)
	}
}

func (s *legacyAuthStream) decodeSimpleHeader(data []byte) ([]byte, int, bool, error) {
	if len(data) < 2 {
		return nil, 0, false, nil
	}
	length := int(binary.BigEndian.Uint16(data[:2]))
	if length < 19 || length >= legacyFrameLimit {
		return nil, 0, false, ErrAuthentication
	}
	if len(data) < length {
		return nil, 0, false, nil
	}
	frame := data[:length]
	if crc32.ChecksumIEEE(frame) != 0xffffffff {
		return nil, 0, false, ErrAuthentication
	}
	position, valid := legacyPayloadPosition(frame, 2, 4)
	if !valid || length-4-position < 12 {
		return nil, 0, false, ErrAuthentication
	}
	payload := frame[position : length-4]
	now := uint32(s.definition.now().Unix())
	timestamp := binary.LittleEndian.Uint32(payload[:4])
	cache := s.definition.replay
	if absoluteInt32(int32(now-timestamp)) > 5*60 || cache == nil ||
		int32(timestamp-uint32(cache.StartedAt().Unix())) < 0 {
		return nil, 0, false, ErrAuthentication
	}
	if !cache.CheckAndInsert(s.definition.name, payload[4:12], 10*time.Minute) {
		return nil, 0, false, ErrAuthentication
	}
	return payload[12:], length, true, nil
}

func (s *legacyAuthStream) decodeSHA1Header(data []byte) ([]byte, int, bool, error) {
	if len(data) < 4 {
		return nil, 0, false, nil
	}
	expectedCRC := crc32.ChecksumIEEE(s.definition.serverKey)
	if s.definition.kind == authSHA1V2 {
		expectedCRC = prefixedCRC("auth_sha1_v2", s.definition.serverKey)
	}
	if binary.LittleEndian.Uint32(data[:4]) != expectedCRC {
		return nil, 0, false, ErrAuthentication
	}
	if len(data) < 6 {
		return nil, 0, false, nil
	}
	length := int(binary.BigEndian.Uint16(data[4:6]))
	if length < 29 || length >= legacyFrameLimit {
		return nil, 0, false, ErrAuthentication
	}
	if len(data) < length {
		return nil, 0, false, nil
	}
	if !validHMACSHA1(s.readIV, s.definition.serverKey, data[:length-10], data[length-10:length]) {
		return nil, 0, false, ErrAuthentication
	}
	position, valid := legacyExtendedPayloadPosition(data[:length], 6, s.definition.kind == authSHA1V2, 10)
	if !valid || length-10-position < 12 {
		return nil, 0, false, ErrAuthentication
	}
	payload := data[position : length-10]
	if s.definition.kind == authSHA1 {
		now := uint32(s.definition.now().Unix())
		timestamp := binary.LittleEndian.Uint32(payload[:4])
		cache := s.definition.replay
		if absoluteInt32(int32(now-timestamp)) > 60*60 || cache == nil ||
			int32(timestamp-uint32(cache.StartedAt().Unix())) < -30*60 {
			return nil, 0, false, ErrAuthentication
		}
	}
	replayToken := payload[:12]
	if s.definition.kind == authSHA1 {
		replayToken = payload[4:12]
	}
	if s.definition.replay == nil || !s.definition.replay.CheckAndInsert(s.definition.name, replayToken, 10*time.Minute) {
		return nil, 0, false, ErrAuthentication
	}
	return payload[12:], length, true, nil
}

func (s *legacyAuthStream) decodeV4Header(data []byte) ([]byte, int, bool, error) {
	if len(data) < 2 {
		return nil, 0, false, nil
	}
	length := int(binary.BigEndian.Uint16(data[:2]))
	if length < 29 || length >= legacyFrameLimit {
		return nil, 0, false, ErrAuthentication
	}
	if len(data) < 6 {
		return nil, 0, false, nil
	}
	crc := crc32.NewIEEE()
	_, _ = crc.Write(data[:2])
	_, _ = crc.Write([]byte("auth_sha1_v4"))
	_, _ = crc.Write(s.definition.serverKey)
	if binary.LittleEndian.Uint32(data[2:6]) != crc.Sum32() {
		return nil, 0, false, ErrAuthentication
	}
	if len(data) < length {
		return nil, 0, false, nil
	}
	if !validHMACSHA1(s.readIV, s.definition.serverKey, data[:length-10], data[length-10:length]) {
		return nil, 0, false, ErrAuthentication
	}
	position, valid := legacyExtendedPayloadPosition(data[:length], 6, true, 10)
	if !valid || length-10-position < 12 {
		return nil, 0, false, ErrAuthentication
	}
	payload := data[position : length-10]
	now := uint32(s.definition.now().Unix())
	if absoluteInt32(int32(now-binary.LittleEndian.Uint32(payload[:4]))) > 24*60*60 {
		return nil, 0, false, ErrAuthentication
	}
	if s.definition.replay == nil || !s.definition.replay.CheckAndInsert(s.definition.name, payload[4:12], 48*time.Hour) {
		return nil, 0, false, ErrAuthentication
	}
	return payload[12:], length, true, nil
}

func (s *legacyAuthStream) decodeFrames(dst, received []byte) ([]byte, []byte, bool, error) {
	feedback := false
	for len(received) >= 2 {
		length := int(binary.BigEndian.Uint16(received[:2]))
		minimum := 7
		if s.definition.kind == authSHA1V4 {
			minimum = 9
		}
		if length < minimum || length >= legacyFrameLimit {
			return nil, nil, false, ErrAuthentication
		}
		if len(received) < length {
			break
		}
		frame := received[:length]
		positionOffset := 2
		extended := s.definition.kind == authSHA1V2
		if s.definition.kind == authSimple {
			if crc32.ChecksumIEEE(frame) != 0xffffffff {
				return nil, nil, false, ErrAuthentication
			}
		} else {
			if binary.LittleEndian.Uint32(frame[length-4:]) != adler32.Checksum(frame[:length-4]) {
				return nil, nil, false, ErrAuthentication
			}
			if s.definition.kind == authSHA1V4 {
				if binary.LittleEndian.Uint16(frame[2:4]) != uint16(crc32.ChecksumIEEE(frame[:2])) {
					return nil, nil, false, ErrAuthentication
				}
				positionOffset = 4
				extended = true
			}
		}
		position, valid := legacyExtendedPayloadPosition(frame, positionOffset, extended, 4)
		if !valid {
			return nil, nil, false, ErrAuthentication
		}
		dst = append(dst, frame[position:length-4]...)
		if s.supportsFeedback() && position == length-4 {
			feedback = true
		}
		received = received[length:]
	}
	return dst, received, feedback, nil
}

func appendLegacyDataFrame(dst, payload []byte, kind legacyAuthKind) ([]byte, error) {
	if kind == authSimple {
		return packCRCFrame(dst, payload)
	}
	prefix, err := legacyRandomPrefix(kind, len(payload), false)
	if err != nil {
		return nil, err
	}
	extra := 0
	if kind == authSHA1V4 {
		extra = 2
	}
	frameLength := 2 + extra + len(prefix) + len(payload) + 4
	start := len(dst)
	dst = append(dst, make([]byte, frameLength)...)
	frame := dst[start:]
	binary.BigEndian.PutUint16(frame[:2], uint16(frameLength))
	position := 2
	if kind == authSHA1V4 {
		binary.LittleEndian.PutUint16(frame[2:4], uint16(crc32.ChecksumIEEE(frame[:2])))
		position = 4
	}
	copy(frame[position:], prefix)
	copy(frame[position+len(prefix):], payload)
	binary.LittleEndian.PutUint32(frame[frameLength-4:], adler32.Checksum(frame[:frameLength-4]))
	return dst, nil
}

func legacyRandomPrefix(kind legacyAuthKind, payloadLength int, auth bool) ([]byte, error) {
	maximum := 16
	if auth && kind == authSHA1 {
		maximum = 128
	}
	if kind == authSHA1V2 {
		if payloadLength > 1300 {
			return []byte{1}, nil
		}
		if payloadLength > 400 {
			maximum = 128
		} else {
			maximum = 1024
		}
	}
	if kind == authSHA1V4 {
		if payloadLength > 1200 {
			return []byte{1}, nil
		}
		maximum = 512
		if payloadLength > 400 {
			maximum = 256
		}
	}
	randomLength, err := randomModulo(maximum)
	if err != nil {
		return nil, err
	}
	header := 1
	if (kind == authSHA1V2 || kind == authSHA1V4) && randomLength >= 128 {
		header = 3
	}
	result := make([]byte, header+randomLength)
	if header == 1 {
		result[0] = byte(len(result))
	} else {
		result[0] = 255
		binary.BigEndian.PutUint16(result[1:3], uint16(len(result)))
	}
	_, err = io.ReadFull(rand.Reader, result[header:])
	return result, err
}

func legacyExtendedPayloadPosition(frame []byte, offset int, extended bool, trailer int) (int, bool) {
	if offset < 0 || offset >= len(frame)-trailer {
		return 0, false
	}
	encoded := int(frame[offset])
	position := offset + encoded
	if extended && encoded == 255 {
		if offset+3 > len(frame)-trailer {
			return 0, false
		}
		position = offset + int(binary.BigEndian.Uint16(frame[offset+1:offset+3]))
	}
	if encoded == 0 || position < offset+1 || position > len(frame)-trailer {
		return 0, false
	}
	return position, true
}

func validHMACSHA1(firstKey, secondKey, data, expected []byte) bool {
	key := make([]byte, 0, len(firstKey)+len(secondKey))
	key = append(key, firstKey...)
	key = append(key, secondKey...)
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(data)
	return hmac.Equal(mac.Sum(nil)[:10], expected)
}

func prefixedCRC(prefix string, key []byte) uint32 {
	crc := crc32.NewIEEE()
	_, _ = io.WriteString(crc, prefix)
	_, _ = crc.Write(key)
	return crc.Sum32()
}

func absoluteInt32(value int32) int64 {
	if value < 0 {
		return -int64(value)
	}
	return int64(value)
}
