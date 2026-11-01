// SPDX-License-Identifier: GPL-3.0-only
// Derived and modified from github.com/MetaCubeX/mihomo transport/simple-obfs.

package obfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/sagernet/sing/common/buf"
)

const (
	tlsChunkSize             = 16 * 1024
	tlsFirstClientHeaderSize = 9*16 - 2
)

var errMalformedTLSObfsRecord = errors.New("shadowsocks: malformed obfs TLS record")

type tlsRecordKind uint8

const (
	tlsApplicationRecord tlsRecordKind = iota
	tlsFirstClientRecord
)

type tlsRecordReader struct {
	header            [tlsFirstClientHeaderSize]byte
	headerRead        int
	headerNeed        int
	payloadRemaining  int
	firstRecordLength int
	kind              tlsRecordKind
	recordReady       bool
}

func (reader *tlsRecordReader) Read(
	conn net.Conn,
	payload []byte,
	kind tlsRecordKind,
) (count int, complete bool, err error) {
	if len(payload) == 0 {
		return 0, false, nil
	}
	if !reader.recordReady {
		if reader.headerNeed == 0 {
			reader.kind = kind
			if kind == tlsFirstClientRecord {
				reader.headerNeed = tlsFirstClientHeaderSize
			} else {
				reader.headerNeed = 5
			}
		} else if reader.kind != kind {
			return 0, false, errMalformedTLSObfsRecord
		}
		for reader.headerRead < reader.headerNeed {
			readCount, readErr := conn.Read(reader.header[reader.headerRead:reader.headerNeed])
			reader.headerRead += readCount
			if readErr != nil {
				return 0, false, readErr
			}
			if readCount == 0 {
				return 0, false, io.ErrNoProgress
			}
		}
		payloadLength, recordLength, parseErr := parseTLSRecordHeader(reader.header[:reader.headerNeed], kind)
		if parseErr != nil {
			return 0, false, parseErr
		}
		reader.headerRead = 0
		reader.headerNeed = 0
		reader.payloadRemaining = payloadLength
		reader.firstRecordLength = recordLength
		reader.recordReady = true
	}
	if reader.payloadRemaining == 0 {
		reader.recordReady = false
		return 0, true, nil
	}
	readLength := min(reader.payloadRemaining, len(payload))
	count, err = conn.Read(payload[:readLength])
	reader.payloadRemaining -= count
	if reader.payloadRemaining == 0 {
		reader.recordReady = false
		complete = true
	}
	if count == 0 && err == nil {
		err = io.ErrNoProgress
	}
	return
}

func parseTLSRecordHeader(header []byte, kind tlsRecordKind) (payloadLength int, recordLength int, err error) {
	switch kind {
	case tlsApplicationRecord:
		if len(header) != 5 || !bytes.Equal(header[:3], []byte{0x17, 0x03, 0x03}) {
			return 0, 0, errMalformedTLSObfsRecord
		}
		payloadLength = int(binary.BigEndian.Uint16(header[3:5]))
		if payloadLength > tlsChunkSize {
			return 0, 0, errMalformedTLSObfsRecord
		}
		return payloadLength, payloadLength, nil
	case tlsFirstClientRecord:
		if len(header) != tlsFirstClientHeaderSize ||
			!bytes.Equal(header[:3], []byte{0x16, 0x03, 0x01}) ||
			header[5] != 0x01 ||
			!bytes.Equal(header[9:11], []byte{0x03, 0x03}) ||
			!bytes.Equal(header[138:140], []byte{0x00, 0x23}) {
			return 0, 0, errMalformedTLSObfsRecord
		}
		recordLength = int(binary.BigEndian.Uint16(header[3:5]))
		handshakeLength := int(header[6])<<16 | int(header[7])<<8 | int(header[8])
		payloadLength = int(binary.BigEndian.Uint16(header[140:142]))
		if handshakeLength+4 != recordLength || recordLength < 137+payloadLength+9+66 {
			return 0, 0, errMalformedTLSObfsRecord
		}
		return payloadLength, recordLength, nil
	default:
		panic("shadowsocks: invalid obfs TLS record kind")
	}
}

type tlsClientHelloTailReader struct {
	header        [9]byte
	headerRead    int
	headerParsed  bool
	hostRemaining int
	tail          [66]byte
	tailRead      int
	recordLength  int
	payloadLength int
}

var tlsClientHelloTail = []byte{
	0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02,
	0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18,
	0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05,
	0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01,
	0x03, 0x02, 0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03,
	0x00, 0x16, 0x00, 0x00,
	0x00, 0x17, 0x00, 0x00,
}

func (reader *tlsClientHelloTailReader) Read(conn net.Conn) error {
	if !reader.headerParsed {
		if err := readTLSState(conn, reader.header[:], &reader.headerRead); err != nil {
			return err
		}
		hostLength := int(binary.BigEndian.Uint16(reader.header[7:9]))
		if !bytes.Equal(reader.header[:2], []byte{0x00, 0x00}) ||
			reader.header[6] != 0 ||
			int(binary.BigEndian.Uint16(reader.header[2:4])) != hostLength+5 ||
			int(binary.BigEndian.Uint16(reader.header[4:6])) != hostLength+3 ||
			reader.recordLength != 137+reader.payloadLength+9+hostLength+len(reader.tail) {
			return errMalformedTLSObfsRecord
		}
		reader.hostRemaining = hostLength
		reader.headerParsed = true
	}
	var scratch [256]byte
	for reader.hostRemaining > 0 {
		count, err := conn.Read(scratch[:min(len(scratch), reader.hostRemaining)])
		reader.hostRemaining -= count
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrNoProgress
		}
	}
	if err := readTLSState(conn, reader.tail[:], &reader.tailRead); err != nil {
		return err
	}
	if !bytes.Equal(reader.tail[:], tlsClientHelloTail) {
		return errMalformedTLSObfsRecord
	}
	return nil
}

func readTLSState(conn net.Conn, target []byte, offset *int) error {
	for *offset < len(target) {
		count, err := conn.Read(target[*offset:])
		*offset += count
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

type tlsServerConn struct {
	net.Conn
	readAccess  sync.Mutex
	writeAccess sync.Mutex
	reader      tlsRecordReader
	tailReader  tlsClientHelloTailReader
	writeVector [2][]byte
	writeHeader [5]byte
	firstRead   bool
	firstWrite  bool
	tailRead    bool
}

func newTLSServerConn(conn net.Conn) net.Conn {
	return &tlsServerConn{Conn: conn, firstRead: true, firstWrite: true}
}

func (conn *tlsServerConn) Read(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	conn.readAccess.Lock()
	defer conn.readAccess.Unlock()
	for {
		if conn.firstRead {
			count, complete, err := conn.reader.Read(conn.Conn, payload, tlsFirstClientRecord)
			if complete {
				conn.firstRead = false
				conn.tailReader.recordLength = conn.reader.firstRecordLength
				conn.tailReader.payloadLength = int(binary.BigEndian.Uint16(conn.reader.header[140:142]))
			}
			if count > 0 || err != nil {
				return count, err
			}
			continue
		}
		if !conn.tailRead {
			if err := conn.tailReader.Read(conn.Conn); err != nil {
				return 0, err
			}
			conn.tailRead = true
		}
		count, complete, err := conn.reader.Read(conn.Conn, payload, tlsApplicationRecord)
		if count > 0 || err != nil {
			return count, err
		}
		if !complete {
			return 0, io.ErrNoProgress
		}
		// Ignore an empty application-data record without exposing (0, nil).
	}
}

func (conn *tlsServerConn) Write(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	conn.writeAccess.Lock()
	defer conn.writeAccess.Unlock()
	written := 0
	for len(payload) > 0 {
		chunkLength := min(len(payload), tlsChunkSize)
		count, err := conn.writeRecord(payload[:chunkLength])
		written += count
		if err != nil {
			return written, err
		}
		payload = payload[chunkLength:]
	}
	return written, nil
}

func (conn *tlsServerConn) writeRecord(payload []byte) (int, error) {
	if conn.firstWrite {
		header := tlsServerHelloPool.Get().(*[tlsServerHelloSize]byte)
		if err := makeServerHelloHeader(header, len(payload)); err != nil {
			tlsServerHelloPool.Put(header)
			return 0, err
		}
		payloadWritten, err := writePrefixedPayloadWithVector(conn.Conn, header[:], payload, &conn.writeVector)
		tlsServerHelloPool.Put(header)
		if err == nil {
			conn.firstWrite = false
		}
		return payloadWritten, err
	}
	conn.writeHeader[0], conn.writeHeader[1], conn.writeHeader[2] = 0x17, 0x03, 0x03
	binary.BigEndian.PutUint16(conn.writeHeader[3:], uint16(len(payload)))
	return writePrefixedPayloadWithVector(conn.Conn, conn.writeHeader[:], payload, &conn.writeVector)
}

func (conn *tlsServerConn) WriteBuffer(buffer *buf.Buffer) error {
	defer buffer.Release()
	count, err := conn.Write(buffer.Bytes())
	if err == nil && count != buffer.Len() {
		err = io.ErrShortWrite
	}
	return err
}

func (conn *tlsServerConn) Upstream() any { return conn.Conn }
