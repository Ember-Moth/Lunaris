// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors
// Adapted from Polaris 56d52fb44958ef3cc2a7fb841cd240f8206234b2.
package ingress

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	singbufio "github.com/sagernet/sing/common/bufio"
)

const (
	proxyV1MaxHeader      = 108
	proxyHeaderReadWindow = 3 * time.Second
)

var (
	proxyV1Magic = []byte("PROXY ")
	proxyV2Magic = []byte("\r\n\r\n\x00\r\nQUIT\n")

	// ErrInvalidProxyHeader identifies a PROXY protocol header that could not be
	// parsed.
	ErrInvalidProxyHeader = errors.New("proxy protocol: invalid header")
)

// AutoProxyListener accepts ordinary TCP connections and PROXY protocol v1/v2
// connections on the same socket. Detection is lazy so a slow peer cannot
// block the listener's accept loop.
//
// A well-formed header is accepted from every peer, matching Polaris. Reported
// addresses are peer-supplied metadata, never authenticated user identity.
// Protocol credentials are still required after detection.
func AutoProxyListener(listener net.Listener) net.Listener {
	if listener == nil {
		return nil
	}
	if _, wrapped := listener.(*autoProxyListener); wrapped {
		return listener
	}
	return &autoProxyListener{Listener: listener}
}

type autoProxyListener struct {
	net.Listener
}

func (listener *autoProxyListener) Accept() (net.Conn, error) {
	conn, err := listener.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return AutoProxyConn(conn), nil
}

// AutoProxyConn detects once, before TLS or the application protocol reads.
func AutoProxyConn(conn net.Conn) net.Conn {
	if _, ok := conn.(*autoProxyConn); ok {
		return conn
	}
	return &autoProxyConn{Conn: conn}
}

// PrepareProxyConn lets non-HTTP transports reject malformed headers before
// opening a camouflage target or invoking any protocol handshake.
func PrepareProxyConn(conn net.Conn) error {
	if c, ok := conn.(*autoProxyConn); ok {
		c.ensureSniffed()
		return c.sniffErr
	}
	return nil
}

type autoProxyConn struct {
	net.Conn

	sniffOnce sync.Once
	sniffErr  error
	sniffDone atomic.Bool

	readMu       sync.Mutex
	readDeadline time.Time
	readVersion  uint64

	cacheMu      sync.Mutex
	prefix       [len("\r\n\r\n\x00\r\nQUIT\n")]byte
	prefixOffset int
	prefixLength int
	extra        []byte
	extraOffset  int
	cacheDrained atomic.Bool

	source      net.Addr
	destination net.Addr
}

func (conn *autoProxyConn) Read(target []byte) (int, error) {
	if len(target) == 0 {
		return 0, nil
	}
	conn.ensureSniffed()
	if conn.sniffErr != nil {
		return 0, conn.sniffErr
	}
	if !conn.cacheDrained.Load() {
		if n := conn.readCache(target); n > 0 {
			return n, nil
		}
	}
	return conn.Conn.Read(target)
}

func (conn *autoProxyConn) WriteTo(writer io.Writer) (int64, error) {
	conn.ensureSniffed()
	if conn.sniffErr != nil {
		return 0, conn.sniffErr
	}
	var written int64
	for !conn.cacheDrained.Load() {
		cache := conn.takeCache()
		if len(cache) == 0 {
			break
		}
		n, err := writer.Write(cache)
		written += int64(n)
		if err != nil {
			return written, err
		}
		if n != len(cache) {
			return written, io.ErrShortWrite
		}
	}
	n, err := singbufio.Copy(writer, conn.Conn)
	return written + n, err
}

func (conn *autoProxyConn) ReadFrom(reader io.Reader) (int64, error) {
	return singbufio.Copy(conn.Conn, reader)
}

func (conn *autoProxyConn) RemoteAddr() net.Addr {
	conn.ensureSniffed()
	if conn.source != nil {
		return conn.source
	}
	return conn.Conn.RemoteAddr()
}

func (conn *autoProxyConn) LocalAddr() net.Addr {
	conn.ensureSniffed()
	if conn.destination != nil {
		return conn.destination
	}
	return conn.Conn.LocalAddr()
}

func (conn *autoProxyConn) SetDeadline(deadline time.Time) error {
	conn.readMu.Lock()
	conn.readDeadline = deadline
	conn.readVersion++
	err := conn.Conn.SetDeadline(deadline)
	conn.readMu.Unlock()
	return err
}

func (conn *autoProxyConn) SetReadDeadline(deadline time.Time) error {
	conn.readMu.Lock()
	conn.readDeadline = deadline
	conn.readVersion++
	err := conn.Conn.SetReadDeadline(deadline)
	conn.readMu.Unlock()
	return err
}

func (conn *autoProxyConn) CloseWrite() error {
	if halfCloser, ok := conn.Conn.(interface{ CloseWrite() error }); ok {
		return halfCloser.CloseWrite()
	}
	return net.ErrClosed
}

func (conn *autoProxyConn) CloseRead() error {
	if halfCloser, ok := conn.Conn.(interface{ CloseRead() error }); ok {
		return halfCloser.CloseRead()
	}
	return net.ErrClosed
}

func (conn *autoProxyConn) ReaderReplaceable() bool {
	return conn.sniffDone.Load() && conn.cacheDrained.Load()
}

func (*autoProxyConn) WriterReplaceable() bool { return true }
func (conn *autoProxyConn) Upstream() any      { return conn.Conn }

func (conn *autoProxyConn) ensureSniffed() {
	conn.sniffOnce.Do(func() {
		conn.sniffErr = conn.sniff()
		conn.cacheMu.Lock()
		drained := conn.cacheEmptyLocked()
		conn.cacheMu.Unlock()
		conn.cacheDrained.Store(drained)
		conn.sniffDone.Store(true)
	})
}

func (conn *autoProxyConn) sniff() error {
	return conn.sniffWithin(proxyHeaderReadWindow)
}

func (conn *autoProxyConn) sniffWithin(readWindow time.Duration) error {
	peeked := conn.prefix[:]
	length, supported, wouldBlock, err := peekProxyHeader(conn.Conn, peeked, false)
	if err != nil {
		return err
	}
	if !supported {
		return conn.sniffConsumingWithin(readWindow)
	}
	if wouldBlock {
		return conn.sniffPeekWithin(readWindow, peeked, true)
	}
	if length == 0 {
		return io.EOF
	}
	prefix := peeked[:length]
	if !matchesProxyMagic(prefix, proxyV1Magic) && !matchesProxyMagic(prefix, proxyV2Magic) {
		return nil
	}
	return conn.sniffPeekWithin(readWindow, prefix, false)
}

func (conn *autoProxyConn) sniffPeekWithin(readWindow time.Duration, peeked []byte, wait bool) error {
	deadlineState, err := conn.beginProxyHeaderRead(readWindow)
	if err != nil {
		return err
	}
	if wait {
		length, supported, _, peekErr := peekProxyHeader(conn.Conn, peeked, true)
		if peekErr != nil {
			err = peekErr
		} else if !supported {
			err = conn.sniffConsuming()
		} else if length == 0 {
			err = io.EOF
		} else {
			err = conn.sniffPeeked(peeked[:length])
		}
	} else {
		err = conn.sniffPeeked(peeked)
	}
	conn.restoreProxyHeaderRead(deadlineState)
	return err
}

func (conn *autoProxyConn) sniffPeeked(prefix []byte) error {
	v1Possible := matchesProxyMagic(prefix, proxyV1Magic)
	v2Possible := matchesProxyMagic(prefix, proxyV2Magic)
	switch {
	case v1Possible && len(prefix) >= len(proxyV1Magic):
		if err := consumeProxyMagic(conn.Conn, proxyV1Magic); err != nil {
			return err
		}
		return conn.readProxyV1(proxyV1Magic)
	case v2Possible && len(prefix) >= len(proxyV2Magic):
		if err := consumeProxyMagic(conn.Conn, proxyV2Magic); err != nil {
			return err
		}
		return conn.readProxyV2()
	case !v1Possible && !v2Possible:
		return nil
	default:
		return conn.sniffConsuming()
	}
}

func (conn *autoProxyConn) sniffConsumingWithin(readWindow time.Duration) error {
	deadlineState, err := conn.beginProxyHeaderRead(readWindow)
	if err != nil {
		return err
	}
	err = conn.sniffConsuming()
	conn.restoreProxyHeaderRead(deadlineState)
	return err
}

func (conn *autoProxyConn) sniffConsuming() error {
	var probe [len("\r\n\r\n\x00\r\nQUIT\n")]byte
	for length := 1; length <= len(probe); length++ {
		if _, err := io.ReadFull(conn.Conn, probe[length-1:length]); err != nil {
			return err
		}
		prefix := probe[:length]
		v1Possible := length <= len(proxyV1Magic) && bytes.Equal(prefix, proxyV1Magic[:length])
		v2Possible := bytes.Equal(prefix, proxyV2Magic[:length])
		if !v1Possible && !v2Possible {
			conn.setPrefix(prefix)
			return nil
		}
		if length == len(proxyV1Magic) && v1Possible {
			return conn.readProxyV1(prefix)
		}
		if length == len(proxyV2Magic) && v2Possible {
			return conn.readProxyV2()
		}
	}
	return ErrInvalidProxyHeader
}

func matchesProxyMagic(probe, magic []byte) bool {
	length := min(len(probe), len(magic))
	return bytes.Equal(probe[:length], magic[:length])
}

func consumeProxyMagic(reader io.Reader, magic []byte) error {
	var actual [len("\r\n\r\n\x00\r\nQUIT\n")]byte
	if _, err := io.ReadFull(reader, actual[:len(magic)]); err != nil {
		return err
	}
	if !bytes.Equal(actual[:len(magic)], magic) {
		return ErrInvalidProxyHeader
	}
	return nil
}

type proxyReadDeadlineState struct {
	original time.Time
	version  uint64
}

func (conn *autoProxyConn) beginProxyHeaderRead(readWindow time.Duration) (proxyReadDeadlineState, error) {
	conn.readMu.Lock()
	original := conn.readDeadline
	version := conn.readVersion
	deadline := time.Now().Add(readWindow)
	if !original.IsZero() && original.Before(deadline) {
		deadline = original
	}
	if err := conn.Conn.SetReadDeadline(deadline); err != nil {
		conn.readMu.Unlock()
		return proxyReadDeadlineState{}, err
	}
	conn.readMu.Unlock()
	return proxyReadDeadlineState{original: original, version: version}, nil
}

func (conn *autoProxyConn) restoreProxyHeaderRead(state proxyReadDeadlineState) {
	conn.readMu.Lock()
	if conn.readVersion == state.version {
		_ = conn.Conn.SetReadDeadline(state.original)
	}
	conn.readMu.Unlock()
}

func (conn *autoProxyConn) readProxyV1(magic []byte) error {
	var header [proxyV1MaxHeader]byte
	total := copy(header[:], magic)
	for total < len(header) {
		n, err := conn.Conn.Read(header[total:])
		total += n
		if end := bytes.Index(header[:total], []byte("\r\n")); end >= 0 {
			if end+2 < total {
				conn.extra = append(conn.extra, header[end+2:total]...)
			}
			return conn.parseProxyV1Line(string(header[:end]))
		}
		if err != nil {
			return err
		}
	}
	return fmt.Errorf("%w: v1 header exceeds %d bytes", ErrInvalidProxyHeader, proxyV1MaxHeader)
}

func (conn *autoProxyConn) parseProxyV1Line(line string) error {
	fields := strings.Fields(line)
	if len(fields) >= 2 && fields[0] == "PROXY" && fields[1] == "UNKNOWN" {
		return nil
	}
	if len(fields) != 6 || fields[0] != "PROXY" || (fields[1] != "TCP4" && fields[1] != "TCP6") {
		return ErrInvalidProxyHeader
	}
	source, err := parseProxyAddr(fields[2], fields[4], fields[1] == "TCP4")
	if err != nil {
		return err
	}
	destination, err := parseProxyAddr(fields[3], fields[5], fields[1] == "TCP4")
	if err != nil {
		return err
	}
	conn.source, conn.destination = source, destination
	return nil
}

func parseProxyAddr(addressText, portText string, ipv4 bool) (*net.TCPAddr, error) {
	address, err := netip.ParseAddr(addressText)
	if err != nil || address.Is4() != ipv4 || address.Zone() != "" {
		return nil, ErrInvalidProxyHeader
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return nil, ErrInvalidProxyHeader
	}
	return net.TCPAddrFromAddrPort(netip.AddrPortFrom(address, uint16(port))), nil
}

func (conn *autoProxyConn) readProxyV2() error {
	var fixed [4]byte
	if _, err := io.ReadFull(conn.Conn, fixed[:]); err != nil {
		return err
	}
	if fixed[0]>>4 != 2 {
		return ErrInvalidProxyHeader
	}
	command := fixed[0] & 0x0f
	family, protocol := fixed[1]>>4, fixed[1]&0x0f
	length := int(fixed[2])<<8 | int(fixed[3])
	if command == 0 {
		return discardProxyPayload(conn.Conn, length)
	}
	if command != 1 || (family != 0 && protocol != 1) {
		return ErrInvalidProxyHeader
	}
	if family == 0 {
		return discardProxyPayload(conn.Conn, length)
	}
	var addressLength int
	switch family {
	case 1:
		addressLength = 12
	case 2:
		addressLength = 36
	default:
		return ErrInvalidProxyHeader
	}
	if length < addressLength {
		return ErrInvalidProxyHeader
	}
	var addresses [36]byte
	if _, err := io.ReadFull(conn.Conn, addresses[:addressLength]); err != nil {
		return err
	}
	if family == 1 {
		source := netip.AddrFrom4([4]byte(addresses[0:4]))
		destination := netip.AddrFrom4([4]byte(addresses[4:8]))
		conn.source = net.TCPAddrFromAddrPort(netip.AddrPortFrom(source, uint16(addresses[8])<<8|uint16(addresses[9])))
		conn.destination = net.TCPAddrFromAddrPort(
			netip.AddrPortFrom(destination, uint16(addresses[10])<<8|uint16(addresses[11])),
		)
	} else {
		source := netip.AddrFrom16([16]byte(addresses[0:16]))
		destination := netip.AddrFrom16([16]byte(addresses[16:32]))
		conn.source = net.TCPAddrFromAddrPort(netip.AddrPortFrom(source,
			uint16(addresses[32])<<8|uint16(addresses[33])))
		conn.destination = net.TCPAddrFromAddrPort(netip.AddrPortFrom(destination,
			uint16(addresses[34])<<8|uint16(addresses[35])))
	}
	return discardProxyPayload(conn.Conn, length-addressLength)
}

func discardProxyPayload(reader io.Reader, length int) error {
	var scratch [512]byte
	for length > 0 {
		chunk := min(length, len(scratch))
		if _, err := io.ReadFull(reader, scratch[:chunk]); err != nil {
			return err
		}
		length -= chunk
	}
	return nil
}

func (conn *autoProxyConn) setPrefix(prefix []byte) {
	conn.cacheMu.Lock()
	conn.prefixLength = copy(conn.prefix[:], prefix)
	conn.cacheMu.Unlock()
}

func (conn *autoProxyConn) readCache(target []byte) int {
	conn.cacheMu.Lock()
	var n int
	if conn.prefixOffset < conn.prefixLength {
		n = copy(target, conn.prefix[conn.prefixOffset:conn.prefixLength])
		conn.prefixOffset += n
	} else if conn.extraOffset < len(conn.extra) {
		n = copy(target, conn.extra[conn.extraOffset:])
		conn.extraOffset += n
		if conn.extraOffset == len(conn.extra) {
			conn.extra = nil
		}
	}
	drained := conn.cacheEmptyLocked()
	conn.cacheMu.Unlock()
	if drained {
		conn.cacheDrained.Store(true)
	}
	return n
}

func (conn *autoProxyConn) takeCache() []byte {
	conn.cacheMu.Lock()
	var cache []byte
	if conn.prefixOffset < conn.prefixLength {
		cache = conn.prefix[conn.prefixOffset:conn.prefixLength]
		conn.prefixOffset = conn.prefixLength
	} else if conn.extraOffset < len(conn.extra) {
		cache = conn.extra[conn.extraOffset:]
		conn.extraOffset = len(conn.extra)
		conn.extra = nil
	}
	drained := conn.cacheEmptyLocked()
	conn.cacheMu.Unlock()
	if drained {
		conn.cacheDrained.Store(true)
	}
	return cache
}

func (conn *autoProxyConn) cacheEmptyLocked() bool {
	return conn.prefixOffset >= conn.prefixLength && conn.extraOffset >= len(conn.extra)
}

var (
	_ net.Listener  = (*autoProxyListener)(nil)
	_ net.Conn      = (*autoProxyConn)(nil)
	_ io.ReaderFrom = (*autoProxyConn)(nil)
	_ io.WriterTo   = (*autoProxyConn)(nil)
)
