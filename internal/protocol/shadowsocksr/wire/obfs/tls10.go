// Copyright 2015-2015 breakwa11
// SPDX-License-Identifier: Apache-2.0
//
// tls1.0_session_auth derives from shadowsocksr-backup/shadowsocksr
// shadowsocks/obfsplugin/obfs_tls.py at 1fe6e89c0752458b18acc343899323a88c44015d.
// Modified by Polaris contributors, 2026-07-31 to 2026-08-28: translated to
// Go and later rewritten for this module; see MODIFICATIONS.md.

package obfs

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"io"
	"slices"
	"sync"
	"time"
)

const (
	tls10MaxRecordLength = 8192
	tls10MaxBuffered     = 16 * 1024
)

var (
	tls10Version          = []byte{0x03, 0x01}
	tls10ChangeCipherSpec = []byte{0x14, 0x03, 0x01, 0x00, 0x01, 0x01}
	tls10HelloTail        = mustDecodeHex("0016c02bc02fc00ac009c013c01400330039002f0035000a0100006fff01000100000a00080006001700180019000b0002010000230000337400000010002900270568322d31360568322d31350568322d313402683208737064792f332e3108687474702f312e31000500050100000000000d001600140401050106010201040305030603020304020202")
)

type tls10Definition struct {
	config  Config
	macPool sync.Pool
}

func newTLS10Definition(config Config) *tls10Definition {
	definition := &tls10Definition{config: config}
	definition.macPool.New = func() any { return newSHA1HMAC() }
	return definition
}

func (*tls10Definition) Overhead() int { return 0 }

func (d *tls10Definition) NewStream() Stream {
	return &tls10Stream{definition: d, config: d.config, mac: d.macPool.Get().(*sha1HMAC)}
}

type tls10State uint8

const (
	tls10NeedHello tls10State = iota
	tls10NeedFinished
	tls10Streaming
	tls10Failed
)

type tls10Stream struct {
	definition *tls10Definition
	config     Config
	state      tls10State
	receive    []byte
	clientID   []byte
	wroteHead  bool
	mac        *sha1HMAC
}

func (s *tls10Stream) Decode(input []byte) ([]byte, bool, bool, error) {
	if s.state == tls10Failed {
		return nil, false, false, ErrAuthentication
	}
	if s.state == tls10Streaming {
		return input, true, false, nil
	}
	if len(s.receive)+len(input) > tls10MaxBuffered {
		return s.fail()
	}
	s.receive = append(s.receive, input...)
	reply := false
	if s.state == tls10NeedHello {
		complete, err := s.consumeHello()
		if err != nil {
			return s.fail()
		}
		if !complete {
			return nil, false, false, nil
		}
		reply = true
	}
	complete, payload, err := s.consumeFinished()
	if err != nil {
		return s.fail()
	}
	if !complete {
		return nil, false, reply, nil
	}
	return payload, true, reply, nil
}

func (s *tls10Stream) consumeHello() (bool, error) {
	if len(s.receive) < 5 {
		return false, nil
	}
	if !bytes.Equal(s.receive[:3], []byte{0x16, 0x03, 0x01}) {
		return false, ErrAuthentication
	}
	recordLength := int(binary.BigEndian.Uint16(s.receive[3:5]))
	if recordLength < 71 || recordLength > tls10MaxRecordLength {
		return false, ErrAuthentication
	}
	total := recordLength + 5
	if len(s.receive) < total {
		return false, nil
	}
	session, verify, err := parseTLS10Hello(s.receive[:total], 0x01)
	if err != nil {
		return false, err
	}
	if !validSHA1(s.macWorker().sum(s.config.ServerKey, session, verify[:22], nil), verify[22:32]) {
		return false, ErrAuthentication
	}
	now := uint32(s.config.Now().Unix())
	if absolute32(int32(now-binary.BigEndian.Uint32(verify[:4]))) > 60*60 {
		return false, ErrAuthentication
	}
	if s.config.Replay == nil || !s.config.Replay.CheckAndInsert("tls1.0_session_auth", verify[:22], 2*time.Hour) {
		return false, ErrAuthentication
	}
	s.clientID = append(s.clientID[:0], session...)
	s.receive = s.receive[total:]
	s.state = tls10NeedFinished
	return true, nil
}

func (s *tls10Stream) consumeFinished() (bool, []byte, error) {
	if len(s.receive) < 6 {
		return false, nil, nil
	}
	if !bytes.Equal(s.receive[:6], tls10ChangeCipherSpec) {
		return false, nil, ErrAuthentication
	}
	if len(s.receive) < 11 {
		return false, nil, nil
	}
	if !bytes.Equal(s.receive[6:11], []byte{0x16, 0x03, 0x01, 0x00, 0x20}) {
		return false, nil, ErrAuthentication
	}
	if len(s.receive) < 43 {
		return false, nil, nil
	}
	if !validSHA1(s.macWorker().sum(s.config.ServerKey, s.clientID, s.receive[:33], nil), s.receive[33:43]) {
		return false, nil, ErrAuthentication
	}
	payload := s.receive[43:]
	s.receive = nil
	s.state = tls10Streaming
	return true, payload, nil
}

func (s *tls10Stream) Encode(dst, input []byte) ([]byte, error) {
	if s.state == tls10Failed {
		return nil, ErrAuthentication
	}
	if !s.wroteHead {
		if len(s.clientID) < 32 || len(s.clientID) > 255 {
			return nil, ErrAuthentication
		}
		s.wroteHead = true
		helloLength := 5 + 4 + 2 + 32 + 1 + len(s.clientID) + len(tls10HelloTail)
		dst = slices.Grow(dst, helloLength+43+len(input))
		helloStart := len(dst)
		var err error
		dst, err = s.appendHello(dst, 0x02, s.clientID)
		if err != nil {
			return nil, err
		}
		helloEnd := len(dst)
		dst, err = s.appendFinished(dst, s.clientID, dst[helloStart:helloEnd])
		if err != nil {
			return nil, err
		}
	}
	return append(dst, input...), nil
}

func (s *tls10Stream) buildHello(messageType byte, session []byte) ([]byte, error) {
	return s.appendHello(nil, messageType, session)
}

func (s *tls10Stream) appendHello(dst []byte, messageType byte, session []byte) ([]byte, error) {
	recordStart := len(dst)
	dst = append(dst, 0x16, 0x03, 0x01, 0, 0, messageType, 0, 0, 0, 0x03, 0x01)
	verifyStart := len(dst)
	dst = append(dst, make([]byte, 32)...)
	verify := dst[verifyStart : verifyStart+32]
	binary.BigEndian.PutUint32(verify[:4], uint32(s.config.Now().Unix()))
	if _, err := io.ReadFull(rand.Reader, verify[4:22]); err != nil {
		return nil, err
	}
	copy(verify[22:], s.macWorker().sum(s.config.ServerKey, session, verify[:22], nil))
	dst = append(dst, byte(len(session)))
	dst = append(dst, session...)
	dst = append(dst, tls10HelloTail...)
	binary.BigEndian.PutUint16(dst[recordStart+7:recordStart+9], uint16(len(dst)-(recordStart+9)))
	binary.BigEndian.PutUint16(dst[recordStart+3:recordStart+5], uint16(len(dst)-(recordStart+5)))
	return dst, nil
}

func (s *tls10Stream) buildFinished(session, prefix []byte) ([]byte, error) {
	return s.appendFinished(nil, session, prefix)
}

func (s *tls10Stream) appendFinished(dst []byte, session, prefix []byte) ([]byte, error) {
	finishedStart := len(dst)
	dst = append(dst, tls10ChangeCipherSpec...)
	dst = append(dst, 0x16, 0x03, 0x01, 0x00, 0x20)
	randomStart := len(dst)
	dst = append(dst, make([]byte, 22)...)
	if _, err := io.ReadFull(rand.Reader, dst[randomStart:]); err != nil {
		return nil, err
	}
	mac := s.macWorker().sum(s.config.ServerKey, session, prefix, dst[finishedStart:])
	return append(dst, mac[:10]...), nil
}

func (s *tls10Stream) fail() ([]byte, bool, bool, error) {
	s.state = tls10Failed
	s.receive = nil
	return nil, false, false, ErrAuthentication
}

func (s *tls10Stream) Close() {
	s.receive = nil
	s.clientID = nil
	if s.definition != nil && s.mac != nil {
		s.definition.macPool.Put(s.mac)
	}
	s.mac = nil
}

func (s *tls10Stream) macWorker() *sha1HMAC {
	if s.mac == nil {
		s.mac = newSHA1HMAC()
	}
	return s.mac
}

func parseTLS10Hello(record []byte, messageType byte) ([]byte, []byte, error) {
	if len(record) < 5 || !bytes.Equal(record[:3], []byte{0x16, 0x03, 0x01}) {
		return nil, nil, ErrAuthentication
	}
	recordLength := int(binary.BigEndian.Uint16(record[3:5]))
	if recordLength < 71 || recordLength > tls10MaxRecordLength || len(record) != recordLength+5 {
		return nil, nil, ErrAuthentication
	}
	handshake := record[5:]
	if len(handshake) < 4 || handshake[0] != messageType || handshake[1] != 0 ||
		int(binary.BigEndian.Uint16(handshake[2:4])) != len(handshake)-4 {
		return nil, nil, ErrAuthentication
	}
	body := handshake[4:]
	if len(body) < 67 || !bytes.Equal(body[:2], tls10Version) {
		return nil, nil, ErrAuthentication
	}
	verify := body[2:34]
	sessionLength := int(body[34])
	if sessionLength < 32 || 35+sessionLength > len(body) {
		return nil, nil, ErrAuthentication
	}
	return body[35 : 35+sessionLength], verify, nil
}

func absolute32(value int32) int64 {
	if value < 0 {
		return -int64(value)
	}
	return int64(value)
}

func mustDecodeHex(value string) []byte {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}
	return decoded
}
