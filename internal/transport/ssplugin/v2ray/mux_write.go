// SPDX-License-Identifier: MPL-2.0
// Derived and modified from XTLS/Xray-core common/mux at b17a88f9b46d.

package v2ray

import (
	"encoding/binary"
	"net"
	"time"
)

func (server *muxServer) writeData(id uint16, header, frame []byte) error {
	payloadLength := len(frame) - len(header)
	binary.BigEndian.PutUint16(header[0:2], 4)
	binary.BigEndian.PutUint16(header[2:4], id)
	header[4], header[5] = statusKeep, optionData
	binary.BigEndian.PutUint16(header[6:8], uint16(payloadLength))
	server.writeMu.Lock()
	defer server.writeMu.Unlock()
	_ = server.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	defer func() { _ = server.conn.SetWriteDeadline(time.Time{}) }()
	return writeAll(server.conn, frame)
}

func (server *muxServer) writeEnd(id uint16) error {
	var frame [6]byte
	binary.BigEndian.PutUint16(frame[0:2], 4)
	binary.BigEndian.PutUint16(frame[2:4], id)
	frame[4] = statusEnd
	server.writeMu.Lock()
	defer server.writeMu.Unlock()
	_ = server.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	defer func() { _ = server.conn.SetWriteDeadline(time.Time{}) }()
	err := writeAll(server.conn, frame[:])
	return err
}

func writeAll(conn net.Conn, payload []byte) error {
	for len(payload) > 0 {
		written, err := conn.Write(payload)
		if err != nil {
			return err
		}
		if written == 0 {
			return net.ErrClosed
		}
		payload = payload[written:]
	}
	return nil
}
