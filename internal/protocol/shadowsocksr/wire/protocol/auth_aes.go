// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package protocol

import (
	"crypto/aes"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"hash"
	"io"
	"math"
	randv2 "math/rand/v2"
	"sync"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/protocol/shadowsocksr/wire/replay"
)

type authAESDefinition struct {
	name       string
	serverKey  []byte
	users      map[[4]byte]Credential
	hash       func() hash.Hash
	now        func() time.Time
	sessions   *replay.Sessions
	maxClients int
	dummy      Credential
	macPool    sync.Pool
}

func newAuthAESDefinition(config Config) *authAESDefinition {
	hashFactory := sha1.New
	if config.Name == "auth_aes128_md5" {
		hashFactory = md5.New
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	definition := &authAESDefinition{name: config.Name, serverKey: config.ServerKey, users: config.Users,
		hash: hashFactory, now: now, sessions: config.Sessions, maxClients: parseMaxClients(config.ProtocolParam)}
	definition.dummy = Credential{Key: make([]byte, hashFactory().Size()), HeaderKey: make([]byte, aes.BlockSize)}
	definition.macPool.New = func() any { return newLegacyMAC(hashFactory) }
	return definition
}

func (*authAESDefinition) Metadata() Metadata { return Metadata{UserFromWire: true} }

func (*authAESDefinition) Overhead() int { return 9 }

func (d *authAESDefinition) NewStream(_ []byte) Stream {
	return &authAESStream{definition: d, mac: d.macPool.Get().(*legacyMAC), packID: 1, receiveID: 1}
}

func (d *authAESDefinition) DecodePacket(_ []byte, packet, _ []byte) ([]byte, [4]byte, error) {
	if len(packet) < 8 {
		return nil, [4]byte{}, ErrAuthentication
	}
	var userID [4]byte
	copy(userID[:], packet[len(packet)-8:len(packet)-4])
	credential, loaded := d.users[userID]
	if !loaded {
		credential = d.dummy
	}
	mac := d.macPool.Get().(*legacyMAC)
	valid := validLegacyMAC(mac.sum(credential.Key, packet[:len(packet)-4]), packet[len(packet)-4:], 4)
	d.macPool.Put(mac)
	if !loaded {
		return nil, [4]byte{}, ErrUnknownUser
	}
	if !valid {
		return nil, [4]byte{}, ErrAuthentication
	}
	return packet[:len(packet)-8], userID, nil
}

func (d *authAESDefinition) EncodePacket(dst, payload []byte, _ [4]byte, _ []byte) ([]byte, error) {
	start := len(dst)
	dst = append(dst, payload...)
	mac := d.macPool.Get().(*legacyMAC)
	sum := mac.sum(d.serverKey, dst[start:])
	dst = append(dst, sum[:4]...)
	d.macPool.Put(mac)
	return dst, nil
}

type authAESStream struct {
	definition    *authAESDefinition
	mac           *legacyMAC
	readIV        []byte
	receive       receiveBuffer
	userID        [4]byte
	userKey       []byte
	clientID      uint32
	packID        uint32
	receiveID     uint32
	sessionActive bool
	authenticated bool
	receivedHead  bool
}

func (s *authAESStream) SetReadIV(iv []byte) { s.readIV = append(s.readIV[:0], iv...) }

func (s *authAESStream) Decode(dst, input []byte) (result []byte, borrowed, reply bool, err error) {
	received, inputBorrowed := s.receive.feed(input)
	defer func() { s.receive.commit(received, inputBorrowed) }()
	result = dst
	if !s.receivedHead {
		if len(received) < 7 {
			return result, false, false, nil
		}
		if !validLegacyMAC(s.mac.sumJoined(s.readIV, s.definition.serverKey, received[:1]), received[1:7], 6) {
			return nil, false, false, ErrAuthentication
		}
		if len(received) < 31 {
			return result, false, false, nil
		}
		if !validLegacyMAC(s.mac.sumJoined(s.readIV, s.definition.serverKey, received[7:27]), received[27:31], 4) {
			return nil, false, false, ErrAuthentication
		}
		copy(s.userID[:], received[7:11])
		credential, loaded := s.definition.users[s.userID]
		if !loaded {
			credential = s.definition.dummy
		}
		header, decryptErr := decryptAESHeader(credential.HeaderKey, received[11:27])
		if decryptErr != nil {
			return nil, false, false, decryptErr
		}
		if !loaded {
			return nil, false, false, ErrUnknownUser
		}
		length := int(binary.LittleEndian.Uint16(header[12:14]))
		paddingLength := int(binary.LittleEndian.Uint16(header[14:16]))
		if length < 35 || length >= legacyFrameLimit || paddingLength > length-35 {
			return nil, false, false, ErrAuthentication
		}
		if len(received) < length {
			return result, false, false, nil
		}
		if !validLegacyMAC(s.mac.sum(credential.Key, received[:length-4]), received[length-4:length], 4) {
			return nil, false, false, ErrAuthentication
		}
		timestamp := binary.LittleEndian.Uint32(header[:4])
		if absoluteInt32(int32(timestamp-uint32(s.definition.now().Unix()))) > 24*60*60 {
			return nil, false, false, ErrAuthentication
		}
		clientID := binary.LittleEndian.Uint32(header[4:8])
		connectionID := binary.LittleEndian.Uint32(header[8:12])
		if s.definition.sessions == nil || !s.definition.sessions.Accept(s.userID, clientID, connectionID, s.definition.maxClients) {
			return nil, false, false, ErrAuthentication
		}
		s.clientID = clientID
		s.sessionActive = true
		s.userKey = credential.Key
		result = append(result, received[31+paddingLength:length-4]...)
		received = received[length:]
		s.receivedHead = true
		s.authenticated = true
		reply = true
	}
	for len(received) > 4 {
		length, position, complete, decodeErr := s.decodeFrameHeader(received)
		if decodeErr != nil {
			return nil, false, false, decodeErr
		}
		if !complete {
			break
		}
		if !validLegacyMAC(s.mac.sumSequence(s.userKey, s.receiveID, received[:length-4]), received[length-4:length], 4) {
			return nil, false, false, ErrAuthentication
		}
		result = append(result, received[position:length-4]...)
		reply = reply || position == length-4
		received = received[length:]
		s.receiveID++
	}
	return result, false, reply, nil
}

func (s *authAESStream) decodeFrameHeader(frame []byte) (length, position int, complete bool, err error) {
	if !validLegacyMAC(s.mac.sumSequence(s.userKey, s.receiveID, frame[:2]), frame[2:4], 2) {
		return 0, 0, false, ErrAuthentication
	}
	length = int(binary.LittleEndian.Uint16(frame[:2]))
	if length < 7 || length >= legacyFrameLimit {
		return 0, 0, false, ErrAuthentication
	}
	if len(frame) < length {
		return length, 0, false, nil
	}
	position = int(frame[4]) + 4
	if frame[4] == 255 {
		if length < 7 {
			return 0, 0, false, ErrAuthentication
		}
		position = int(binary.LittleEndian.Uint16(frame[5:7])) + 4
	}
	if position < 5 || position > length-4 {
		return 0, 0, false, ErrAuthentication
	}
	return length, position, true, nil
}

func (s *authAESStream) Encode(dst, payload []byte) ([]byte, error) {
	originalLength := len(payload)
	for len(payload) > legacyUnitLength {
		var err error
		dst, err = s.appendFrame(dst, payload[:legacyUnitLength], originalLength)
		if err != nil {
			return nil, err
		}
		payload = payload[legacyUnitLength:]
	}
	return s.appendFrame(dst, payload, originalLength)
}

func (s *authAESStream) appendFrame(dst, payload []byte, fullLength int) ([]byte, error) {
	paddingLength := authAESPaddingLength(len(payload), fullLength)
	prefixLength := paddingLength + 1
	frameLength := 4 + prefixLength + len(payload) + 4
	start := len(dst)
	dst = append(dst, make([]byte, frameLength)...)
	frame := dst[start:]
	binary.LittleEndian.PutUint16(frame[:2], uint16(frameLength))
	copy(frame[2:4], s.mac.sumSequence(s.userKey, s.packID, frame[:2]))
	position := 4
	if paddingLength < 128 {
		frame[position] = byte(paddingLength + 1)
		position++
		if _, err := io.ReadFull(rand.Reader, frame[position:position+paddingLength]); err != nil {
			return nil, err
		}
		position += paddingLength
	} else {
		frame[position] = 255
		binary.LittleEndian.PutUint16(frame[position+1:position+3], uint16(paddingLength+1))
		position += 3
		if _, err := io.ReadFull(rand.Reader, frame[position:position+paddingLength-2]); err != nil {
			return nil, err
		}
		position += paddingLength - 2
	}
	copy(frame[position:], payload)
	copy(frame[frameLength-4:], s.mac.sumSequence(s.userKey, s.packID, frame[:frameLength-4]))
	s.packID++
	return dst, nil
}

func (s *authAESStream) UserID() ([4]byte, bool) { return s.userID, s.authenticated }

func (s *authAESStream) Close() {
	s.receive.release()
	if s.mac != nil {
		s.definition.macPool.Put(s.mac)
		s.mac = nil
	}
	if s.sessionActive {
		s.definition.sessions.Release(s.userID, s.clientID)
		s.sessionActive = false
	}
}

func decryptAESHeader(key, ciphertext []byte) ([16]byte, error) {
	var plaintext [16]byte
	block, err := aes.NewCipher(key)
	if err != nil {
		return plaintext, err
	}
	// CBC with an all-zero IV is identical to a single raw AES block for the
	// one-block SSR authentication header.
	block.Decrypt(plaintext[:], ciphertext)
	return plaintext, nil
}

func authAESPaddingLength(payloadLength, fullLength int) int {
	if fullLength >= 32768-9 {
		return 0
	}
	remainder := 1460 - payloadLength - 9
	if remainder == 0 {
		return 0
	}
	if remainder < 0 {
		if remainder > -1460 {
			return trapezoidRandomInt(remainder+1460, -0.3)
		}
		return randv2.IntN(33)
	}
	if payloadLength > 900 {
		return randv2.IntN(remainder + 1)
	}
	return trapezoidRandomInt(remainder, -0.3)
}

func trapezoidRandomInt(maximum int, d float64) int {
	if maximum <= 0 {
		return 0
	}
	sample := randv2.Float64()
	if d == 0 {
		return int(sample * float64(maximum))
	}
	tmp := 1 - d
	value := (math.Sqrt(tmp*tmp+4*d*sample) - tmp) / (2 * d)
	return int(value * float64(maximum))
}
