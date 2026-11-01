// Copyright 2015-2015 breakwa11
// SPDX-License-Identifier: Apache-2.0
//
// verify_simple and verify_sha1 derive from shadowsocksr-backup/shadowsocksr
// shadowsocks/obfsplugin/verify.py at db6629a1307ed38eb507bd926ad1503e90bc4eb1.
// Modified by Polaris contributors, 2026-07-31 to 2026-08-28: translated to
// Go and later rewritten for this module; see MODIFICATIONS.md.

package protocol

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"hash/crc32"
)

type verifySimpleDefinition struct {
	userID [4]byte
}

func (*verifySimpleDefinition) Metadata() Metadata { return Metadata{SingleUser: true} }

func (*verifySimpleDefinition) Overhead() int { return 4 }

func (d *verifySimpleDefinition) NewStream(_ []byte) Stream {
	return &verifySimpleStream{userID: d.userID}
}

func (d *verifySimpleDefinition) DecodePacket(_ []byte, packet, _ []byte) ([]byte, [4]byte, error) {
	return packet, d.userID, nil
}

func (*verifySimpleDefinition) EncodePacket(dst, payload []byte, _ [4]byte, _ []byte) ([]byte, error) {
	return append(dst, payload...), nil
}

type verifySimpleStream struct {
	userID        [4]byte
	receive       receiveBuffer
	authenticated bool
}

func (*verifySimpleStream) SetReadIV([]byte) {}

func (s *verifySimpleStream) Decode(dst, input []byte) (result []byte, borrowed, reply bool, err error) {
	received, inputBorrowed := s.receive.feed(input)
	defer func() { s.receive.commit(received, inputBorrowed) }()
	result = dst
	for len(received) >= 2 {
		length := int(binary.BigEndian.Uint16(received[:2]))
		if length < 7 || length >= legacyFrameLimit {
			return nil, false, false, ErrAuthentication
		}
		if len(received) < length {
			break
		}
		frame := received[:length]
		if crc32.ChecksumIEEE(frame) != 0xffffffff {
			return nil, false, false, ErrAuthentication
		}
		position, valid := legacyPayloadPosition(frame, 2, 4)
		if !valid {
			return nil, false, false, ErrAuthentication
		}
		result = append(result, frame[position:length-4]...)
		s.authenticated = true
		received = received[length:]
	}
	return result, false, false, nil
}

func (*verifySimpleStream) Encode(dst, payload []byte) ([]byte, error) {
	return packCRCFrames(dst, payload)
}

func (s *verifySimpleStream) UserID() ([4]byte, bool) { return s.userID, s.authenticated }

func (s *verifySimpleStream) Close() { s.receive.release() }

type verifySHA1Definition struct {
	userID    [4]byte
	serverKey []byte
}

func (*verifySHA1Definition) Metadata() Metadata { return Metadata{SingleUser: true} }

func (*verifySHA1Definition) Overhead() int { return 4 }

func (d *verifySHA1Definition) NewStream(_ []byte) Stream {
	return &verifySHA1Stream{userID: d.userID, serverKey: d.serverKey}
}

func (d *verifySHA1Definition) DecodePacket(_ []byte, packet, iv []byte) ([]byte, [4]byte, error) {
	if len(packet) <= 10 || packet[0]&0x10 == 0 {
		return nil, [4]byte{}, ErrAuthentication
	}
	payload := packet[:len(packet)-10]
	key := make([]byte, 0, len(iv)+len(d.serverKey))
	key = append(key, iv...)
	key = append(key, d.serverKey...)
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(payload)
	if !hmac.Equal(mac.Sum(nil)[:10], packet[len(payload):]) {
		return nil, [4]byte{}, ErrAuthentication
	}
	payload[0] &^= 0x10
	return payload, d.userID, nil
}

func (*verifySHA1Definition) EncodePacket(dst, payload []byte, _ [4]byte, _ []byte) ([]byte, error) {
	return append(dst, payload...), nil
}

type verifySHA1Stream struct {
	userID         [4]byte
	serverKey      []byte
	readIV         []byte
	receive        receiveBuffer
	receiveID      uint32
	receivedHeader bool
	authenticated  bool
}

func (s *verifySHA1Stream) SetReadIV(iv []byte) {
	s.readIV = append(s.readIV[:0], iv...)
}

func (s *verifySHA1Stream) Decode(dst, input []byte) (result []byte, borrowed, reply bool, err error) {
	received, inputBorrowed := s.receive.feed(input)
	defer func() { s.receive.commit(received, inputBorrowed) }()
	result = dst
	if !s.receivedHeader {
		if len(received) == 0 {
			return result, false, false, nil
		}
		if received[0]&0x10 == 0 {
			return nil, false, false, ErrAuthentication
		}
		headerLength, complete := socksHeaderLength(received)
		if !complete || len(received) < headerLength+10 {
			return result, false, false, nil
		}
		key := make([]byte, 0, len(s.readIV)+len(s.serverKey))
		key = append(key, s.readIV...)
		key = append(key, s.serverKey...)
		mac := hmac.New(sha1.New, key)
		_, _ = mac.Write(received[:headerLength])
		if !hmac.Equal(mac.Sum(nil)[:10], received[headerLength:headerLength+10]) {
			return nil, false, false, ErrAuthentication
		}
		start := len(result)
		result = append(result, received[:headerLength]...)
		result[start] &^= 0x10
		received = received[headerLength+10:]
		s.receivedHeader = true
		s.authenticated = true
	}
	for len(received) >= 2 {
		payloadLength := int(binary.BigEndian.Uint16(received[:2]))
		frameLength := payloadLength + 12
		if payloadLength > legacyUnitLength || frameLength > legacyFrameLimit {
			return nil, false, false, ErrAuthentication
		}
		if len(received) < frameLength {
			break
		}
		key := make([]byte, len(s.readIV)+4)
		copy(key, s.readIV)
		binary.BigEndian.PutUint32(key[len(key)-4:], s.receiveID)
		mac := hmac.New(sha1.New, key)
		_, _ = mac.Write(received[12:frameLength])
		if !hmac.Equal(mac.Sum(nil)[:10], received[2:12]) {
			return nil, false, false, ErrAuthentication
		}
		result = append(result, received[12:frameLength]...)
		received = received[frameLength:]
		s.receiveID++
	}
	return result, false, false, nil
}

func (*verifySHA1Stream) Encode(dst, payload []byte) ([]byte, error) {
	return append(dst, payload...), nil
}

func (s *verifySHA1Stream) UserID() ([4]byte, bool) { return s.userID, s.authenticated }

func (s *verifySHA1Stream) Close() { s.receive.release() }
