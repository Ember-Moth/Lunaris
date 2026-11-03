// SPDX-License-Identifier: GPL-3.0-only
package trojan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"

	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
)

func WriteClientRequest(conn net.Conn, password string, dst M.Socksaddr, packet bool) error {
	sum := sha256.Sum224([]byte(password))
	var request bytes.Buffer
	request.WriteString(hex.EncodeToString(sum[:]) + "\r\n")
	command := byte(1)
	if packet {
		command = 3
	}
	request.WriteByte(command)
	if err := M.SocksaddrSerializer.WriteAddrPort(&request, dst); err != nil {
		return err
	}
	request.WriteString("\r\n")
	_, err := io.Copy(conn, &request)
	return err
}

func NewClientPacketConn(conn net.Conn) net.PacketConn {
	return bufio.NewNetPacketConn(&packetConn{Conn: conn})
}
