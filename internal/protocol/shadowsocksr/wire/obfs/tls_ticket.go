// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package obfs

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"slices"
	"strconv"
	"sync"
	"time"
)

// SSR peers may coalesce an entire 16-bit application record before Finished.
// Keep room for that record plus the next socket read while framing it.
const tlsTicketMaxBuffered = 128 * 1024

var tlsTicketHelloTail = []byte{0xc0, 0x2f, 0x00, 0x00, 0x05, 0xff, 0x01, 0x00, 0x01, 0x00}

type tlsTicketDefinition struct {
	config            Config
	maximumDifference int64
	macPool           sync.Pool
}

func newTLSTicketDefinition(config Config) *tlsTicketDefinition {
	maximumDifference := int64(24 * 60 * 60)
	if parsed, err := strconv.ParseInt(config.Param, 10, 64); err == nil {
		maximumDifference = parsed
	}
	definition := &tlsTicketDefinition{config: config, maximumDifference: maximumDifference}
	definition.macPool.New = func() any { return newSHA1HMAC() }
	return definition
}

func (*tlsTicketDefinition) Overhead() int { return 5 }

func (d *tlsTicketDefinition) NewStream() Stream {
	return &tlsTicketStream{
		definition: d, config: d.config, maximumDifference: d.maximumDifference, mac: d.macPool.Get().(*sha1HMAC),
	}
}

type tlsTicketState uint8

const (
	tlsTicketNeedHello tlsTicketState = iota
	tlsTicketNeedFinished
	tlsTicketStreaming
	tlsTicketFailed
)

type tlsTicketStream struct {
	definition        *tlsTicketDefinition
	config            Config
	state             tlsTicketState
	receive           []byte
	decoded           []byte
	clientID          []byte
	wroteHead         bool
	maximumDifference int64
	mac               *sha1HMAC
}

func (s *tlsTicketStream) Decode(input []byte) ([]byte, bool, bool, error) {
	if s.state == tlsTicketFailed {
		return nil, false, false, ErrAuthentication
	}
	if s.state == tlsTicketStreaming && len(s.receive) == 0 {
		if len(input) > tlsTicketMaxBuffered {
			return s.fail()
		}
		return s.consumeApplication(input, false, false)
	}
	if len(s.receive)+len(input) > tlsTicketMaxBuffered {
		return s.fail()
	}
	s.receive = append(s.receive, input...)
	if s.state == tlsTicketStreaming {
		return s.consumeApplication(s.receive, false, true)
	}
	reply := false
	if s.state == tlsTicketNeedHello {
		complete, err := s.consumeHello()
		if err != nil {
			return s.fail()
		}
		if !complete {
			return nil, false, false, nil
		}
		reply = true
	}
	complete, err := s.consumeFinished()
	if err != nil {
		return s.fail()
	}
	if !complete {
		return nil, false, reply, nil
	}
	data, decrypt, _, err := s.consumeApplication(s.receive, reply, true)
	return data, decrypt, reply, err
}

func (s *tlsTicketStream) consumeHello() (bool, error) {
	if len(s.receive) < 5 {
		return false, nil
	}
	if !bytes.Equal(s.receive[:3], []byte{0x16, 0x03, 0x01}) {
		return false, ErrAuthentication
	}
	recordLength := int(binary.BigEndian.Uint16(s.receive[3:5]))
	if recordLength <= 0 || recordLength > 16*1024 {
		return false, ErrAuthentication
	}
	total := 5 + recordLength
	if len(s.receive) < total {
		return false, nil
	}
	hello := s.receive[5:total]
	if len(hello) < 4+2+32+1 || hello[0] != 0x01 || hello[1] != 0 ||
		int(binary.BigEndian.Uint16(hello[2:4])) != len(hello)-4 || !bytes.Equal(hello[4:6], []byte{0x03, 0x03}) {
		return false, ErrAuthentication
	}
	verify := hello[6:38]
	sessionLength := int(hello[38])
	if sessionLength < 32 || 39+sessionLength > len(hello) {
		return false, ErrAuthentication
	}
	session := hello[39 : 39+sessionLength]
	if !validSHA1(s.macWorker().sum(s.config.ServerKey, session, verify[:22], nil), verify[22:32]) {
		return false, ErrAuthentication
	}
	if s.maximumDifference > 0 && absolute32(int32(uint32(s.config.Now().Unix())-binary.BigEndian.Uint32(verify[:4]))) > s.maximumDifference {
		return false, ErrAuthentication
	}
	if s.config.Replay == nil || !s.config.Replay.CheckAndInsert(s.config.Name, verify[:22], 24*time.Hour) {
		return false, ErrAuthentication
	}
	s.clientID = append(s.clientID[:0], session...)
	s.receive = s.receive[total:]
	s.state = tlsTicketNeedFinished
	return true, nil
}

func (s *tlsTicketStream) consumeFinished() (bool, error) {
	if len(s.receive) < 11 {
		return false, nil
	}
	if !bytes.Equal(s.receive[:6], []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}) ||
		!bytes.Equal(s.receive[6:9], []byte{0x16, 0x03, 0x03}) {
		return false, ErrAuthentication
	}
	recordLength := int(binary.BigEndian.Uint16(s.receive[9:11]))
	if recordLength < 10 || recordLength > 16*1024 {
		return false, ErrAuthentication
	}
	verifyLength := recordLength + 1
	if len(s.receive) < verifyLength+10 {
		return false, nil
	}
	if !validSHA1(s.macWorker().sum(s.config.ServerKey, s.clientID, s.receive[:verifyLength], nil), s.receive[verifyLength:verifyLength+10]) {
		return false, ErrAuthentication
	}
	s.receive = s.receive[verifyLength+10:]
	s.state = tlsTicketStreaming
	return true, nil
}

func (s *tlsTicketStream) consumeApplication(input []byte, reply, buffered bool) ([]byte, bool, bool, error) {
	offset := 0
	recordCount := 0
	firstStart := 0
	firstEnd := 0
	for len(input)-offset >= 5 {
		record := input[offset:]
		if !bytes.Equal(record[:3], []byte{0x17, 0x03, 0x03}) {
			return nil, false, false, ErrAuthentication
		}
		length := int(binary.BigEndian.Uint16(record[3:5]))
		if len(record) < length+5 {
			break
		}
		if recordCount == 0 {
			firstStart = offset + 5
			firstEnd = firstStart + length
		}
		recordCount++
		offset += length + 5
	}

	if recordCount == 1 && offset == len(input) {
		if buffered {
			s.receive = input[:0]
		}
		data := input[firstStart:firstEnd]
		return data, len(data) > 0, reply, nil
	}

	s.decoded = s.decoded[:0]
	for position := 0; position < offset; {
		length := int(binary.BigEndian.Uint16(input[position+3 : position+5]))
		s.decoded = append(s.decoded, input[position+5:position+5+length]...)
		position += length + 5
	}
	remainder := input[offset:]
	if buffered {
		copy(input, remainder)
		s.receive = input[:len(remainder)]
	} else if len(remainder) > 0 {
		s.receive = append(s.receive[:0], remainder...)
	}
	return s.decoded, len(s.decoded) > 0, reply, nil
}

func (s *tlsTicketStream) Encode(dst, input []byte) ([]byte, error) {
	if s.state == tlsTicketFailed {
		return nil, ErrAuthentication
	}
	if !s.wroteHead {
		if len(s.clientID) < 32 {
			return nil, ErrAuthentication
		}
		s.wroteHead = true
		recordCount := (len(input) + 2047) / 2048
		helloLength := 5 + 4 + 2 + 32 + 1 + len(s.clientID) + len(tlsTicketHelloTail)
		dst = slices.Grow(dst, helloLength+43+len(input)+recordCount*5)
		helloStart := len(dst)
		dst = append(dst, 0x16, 0x03, 0x03, 0, 0, 0x02, 0, 0, 0, 0x03, 0x03)
		verifyStart := len(dst)
		dst = append(dst, make([]byte, 32)...)
		verify := dst[verifyStart : verifyStart+32]
		binary.BigEndian.PutUint32(verify[:4], uint32(s.config.Now().Unix()))
		if _, err := io.ReadFull(rand.Reader, verify[4:22]); err != nil {
			return nil, err
		}
		copy(verify[22:], s.macWorker().sum(s.config.ServerKey, s.clientID, verify[:22], nil))
		dst = append(dst, byte(len(s.clientID)))
		dst = append(dst, s.clientID...)
		dst = append(dst, tlsTicketHelloTail...)
		binary.BigEndian.PutUint16(dst[helloStart+7:helloStart+9], uint16(len(dst)-(helloStart+9)))
		binary.BigEndian.PutUint16(dst[helloStart+3:helloStart+5], uint16(len(dst)-(helloStart+5)))
		dst = append(dst, 0x14, 0x03, 0x03, 0x00, 0x01, 0x01)
		dst = append(dst, 0x16, 0x03, 0x03, 0x00, 0x20)
		randomStart := len(dst)
		dst = append(dst, make([]byte, 22)...)
		if _, err := io.ReadFull(rand.Reader, dst[randomStart:]); err != nil {
			return nil, err
		}
		mac := s.macWorker().sum(s.config.ServerKey, s.clientID, dst, nil)
		dst = append(dst, mac[:10]...)
	}
	for len(input) > 0 {
		length := min(len(input), 2048)
		dst = append(dst, 0x17, 0x03, 0x03, byte(length>>8), byte(length))
		dst = append(dst, input[:length]...)
		input = input[length:]
	}
	return dst, nil
}

func (s *tlsTicketStream) fail() ([]byte, bool, bool, error) {
	s.state = tlsTicketFailed
	s.receive = nil
	return nil, false, false, ErrAuthentication
}

func (s *tlsTicketStream) Close() {
	s.receive = nil
	s.decoded = nil
	s.clientID = nil
	if s.definition != nil && s.mac != nil {
		s.definition.macPool.Put(s.mac)
	}
	s.mac = nil
}

func (s *tlsTicketStream) macWorker() *sha1HMAC {
	if s.mac == nil {
		s.mac = newSHA1HMAC()
	}
	return s.mac
}
