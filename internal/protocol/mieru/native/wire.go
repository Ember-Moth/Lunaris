// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package native

import (
	"encoding/binary"
	"errors"
	"time"
)

const (
	metadataLength       = 32
	maxSessionPayload    = 1024
	maxPDU               = 32 * 1024
	nonceSize            = 24
	authTagSize          = 16
	packetHeaderSize     = nonceSize + metadataLength + authTagSize
	packetOverhead       = packetHeaderSize + authTagSize
	defaultMTU           = 1500
	maxTimestampDeltaMin = 1
)

type protocolType byte

const (
	closeConnRequest protocolType = iota
	closeConnResponse
	openSessionRequest
	openSessionResponse
	closeSessionRequest
	closeSessionResponse
	dataClientToServer
	dataServerToClient
	ackClientToServer
	ackServerToClient
)

type metadata struct {
	protocol   protocolType
	sessionID  uint32
	seq        uint32
	status     byte
	unAckSeq   uint32
	windowSize uint16
	fragment   byte
	prefixLen  byte
	payloadLen uint16
	suffixLen  byte
}

func (m *metadata) sessionProtocol() bool {
	return m.protocol >= openSessionRequest && m.protocol <= closeSessionResponse
}

func (m *metadata) dataProtocol() bool {
	return m.protocol >= dataClientToServer && m.protocol <= ackServerToClient
}

func (m *metadata) marshal(dst []byte, now time.Time) []byte {
	if cap(dst) < metadataLength {
		dst = make([]byte, metadataLength)
	} else {
		dst = dst[:metadataLength]
		clear(dst)
	}
	dst[0] = byte(m.protocol)
	binary.BigEndian.PutUint32(dst[2:6], uint32(now.Unix()/60))
	binary.BigEndian.PutUint32(dst[6:10], m.sessionID)
	binary.BigEndian.PutUint32(dst[10:14], m.seq)
	if m.sessionProtocol() {
		dst[14] = m.status
		binary.BigEndian.PutUint16(dst[15:17], m.payloadLen)
		dst[17] = m.suffixLen
	} else {
		binary.BigEndian.PutUint32(dst[14:18], m.unAckSeq)
		binary.BigEndian.PutUint16(dst[18:20], m.windowSize)
		dst[20] = m.fragment
		dst[21] = m.prefixLen
		binary.BigEndian.PutUint16(dst[22:24], m.payloadLen)
		dst[24] = m.suffixLen
	}
	return dst
}

func parseMetadata(src []byte, now time.Time) (metadata, error) {
	if len(src) != metadataLength {
		return metadata{}, errors.New("mieru: invalid metadata length")
	}
	m := metadata{protocol: protocolType(src[0]), sessionID: binary.BigEndian.Uint32(src[6:10]), seq: binary.BigEndian.Uint32(src[10:14])}
	timestamp := binary.BigEndian.Uint32(src[2:6])
	current := uint32(now.Unix() / 60)
	if delta := int64(current) - int64(timestamp); delta < -maxTimestampDeltaMin || delta > maxTimestampDeltaMin {
		return metadata{}, errors.New("mieru: invalid metadata timestamp")
	}
	if m.sessionProtocol() {
		m.status = src[14]
		m.payloadLen = binary.BigEndian.Uint16(src[15:17])
		m.suffixLen = src[17]
		if m.payloadLen > maxSessionPayload {
			return metadata{}, errors.New("mieru: session payload too large")
		}
		return m, nil
	}
	if m.dataProtocol() {
		m.unAckSeq = binary.BigEndian.Uint32(src[14:18])
		m.windowSize = binary.BigEndian.Uint16(src[18:20])
		m.fragment = src[20]
		m.prefixLen = src[21]
		m.payloadLen = binary.BigEndian.Uint16(src[22:24])
		m.suffixLen = src[24]
		if m.payloadLen > maxPDU {
			return metadata{}, errors.New("mieru: data payload too large")
		}
		return m, nil
	}
	return metadata{}, errors.New("mieru: unsupported protocol type")
}

type segment struct {
	meta    metadata
	payload []byte
}
