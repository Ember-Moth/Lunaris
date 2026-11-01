// SPDX-License-Identifier: GPL-3.0-only
// Derived and modified from github.com/MetaCubeX/mihomo transport/simple-obfs.

package obfs

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/sagernet/sing/common/buf"
)

const (
	maxHTTPObfsHeader = 64 * 1024
	httpHeaderChunk   = 4 * 1024
)

var (
	errInvalidHTTPObfsRequest = errors.New("shadowsocks: invalid obfs HTTP request")
	errHTTPObfsHeaderTooLarge = errors.New("shadowsocks: obfs HTTP header is too large")
)

// Config selects the simple-obfs mode, http or tls.
type Config struct {
	Mode string
}

// Wrap strips the simple-obfs framing of the selected mode from a connection.
func Wrap(config Config, conn net.Conn) net.Conn {
	if config.Mode == "http" {
		return &httpServerConn{Conn: conn}
	}
	return newTLSServerConn(conn)
}

type httpServerConn struct {
	net.Conn
	readAccess  sync.Mutex
	writeAccess sync.Mutex
	header      []byte
	pending     []byte
	parsed      bool
	wrote       bool
}

func (conn *httpServerConn) Read(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	conn.readAccess.Lock()
	defer conn.readAccess.Unlock()
	if !conn.parsed {
		if err := conn.readRequest(); err != nil {
			return 0, err
		}
	}
	if len(conn.pending) > 0 {
		count := copy(payload, conn.pending)
		conn.pending = conn.pending[count:]
		if len(conn.pending) == 0 {
			conn.pending = nil
		}
		return count, nil
	}
	return conn.Conn.Read(payload)
}

func (conn *httpServerConn) readRequest() error {
	for {
		if headerEnd := bytes.Index(conn.header, []byte("\r\n\r\n")); headerEnd >= 0 {
			headerEnd += 4
			request, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(conn.header[:headerEnd])))
			if err != nil {
				return errInvalidHTTPObfsRequest
			}
			_ = request.Body.Close()
			if request.Method != http.MethodGet ||
				!headerHasToken(request.Header, "Connection", "upgrade") ||
				len(request.TransferEncoding) != 0 {
				return errInvalidHTTPObfsRequest
			}
			// A read may contain the request header and the first Shadowsocks bytes.
			// Preserve only that read-ahead and release the bounded header buffer.
			conn.pending = bytes.Clone(conn.header[headerEnd:])
			conn.header = nil
			conn.parsed = true
			return nil
		}
		if len(conn.header) >= maxHTTPObfsHeader {
			return errHTTPObfsHeaderTooLarge
		}
		readSize := min(httpHeaderChunk, maxHTTPObfsHeader-len(conn.header))
		oldLength := len(conn.header)
		conn.header = append(conn.header, make([]byte, readSize)...)
		count, err := conn.Conn.Read(conn.header[oldLength:])
		conn.header = conn.header[:oldLength+count]
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrNoProgress
		}
	}
}

func (conn *httpServerConn) Write(payload []byte) (int, error) {
	conn.writeAccess.Lock()
	defer conn.writeAccess.Unlock()
	if conn.wrote {
		count, err := conn.Conn.Write(payload)
		if err == nil && count != len(payload) {
			err = io.ErrShortWrite
		}
		return count, err
	}
	//nolint:gosec // the fake server version is camouflage, not a secret
	response := fmt.Appendf(nil,
		"HTTP/1.1 101 Switching Protocols\r\nServer: nginx/1.%d.%d\r\nDate: %s\r\n"+
			"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
		rand.IntN(11), rand.IntN(12), time.Now().Format(time.RFC1123))
	payloadWritten, err := writePrefixedPayload(conn.Conn, response, payload)
	if err == nil {
		conn.wrote = true
	}
	return payloadWritten, err
}

func (conn *httpServerConn) WriteBuffer(buffer *buf.Buffer) error {
	defer buffer.Release()
	count, err := conn.Write(buffer.Bytes())
	if err == nil && count != buffer.Len() {
		err = io.ErrShortWrite
	}
	return err
}

func (conn *httpServerConn) Upstream() any { return conn.Conn }

func (conn *httpServerConn) ReaderReplaceable() bool {
	conn.readAccess.Lock()
	defer conn.readAccess.Unlock()
	return conn.parsed && len(conn.pending) == 0
}

func (conn *httpServerConn) WriterReplaceable() bool {
	conn.writeAccess.Lock()
	defer conn.writeAccess.Unlock()
	return conn.wrote
}

func headerHasToken(header http.Header, key, token string) bool {
	for value := range bytes.SplitSeq([]byte(header.Get(key)), []byte(",")) {
		if bytes.EqualFold(bytes.TrimSpace(value), []byte(token)) {
			return true
		}
	}
	return false
}
