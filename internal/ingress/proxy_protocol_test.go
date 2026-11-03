// SPDX-License-Identifier: GPL-3.0-only
package ingress

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func proxyV2(family byte, command byte, source, destination net.IP, extra []byte) []byte {
	addresses := append(append([]byte(nil), source...), destination...)
	addresses = binary.BigEndian.AppendUint16(addresses, 12345)
	addresses = binary.BigEndian.AppendUint16(addresses, 443)
	addresses = append(addresses, extra...)
	header := append([]byte(nil), proxyV2Magic...)
	header = append(header, 0x20|command, family)
	header = binary.BigEndian.AppendUint16(header, uint16(len(addresses)))
	return append(header, addresses...)
}
func TestAutomaticProxyHeadersAndOrdinaryBytes(t *testing.T) {
	v4 := proxyV2(0x11, 1, net.ParseIP("198.18.0.10").To4(), net.ParseIP("198.19.0.20").To4(), []byte{0x05, 0, 2, 1, 2})
	v6 := proxyV2(0x21, 1, net.ParseIP("fd00::10").To16(), net.ParseIP("fd00::20").To16(), nil)
	for _, tc := range []struct {
		name                string
		header, payload     []byte
		source, destination string
	}{
		{"zero-ports", []byte("PROXY TCP4 198.18.0.10 198.19.0.20 0 0\r\n"), []byte("payload"), "198.18.0.10:0", "198.19.0.20:0"},
		{"v1", []byte("PROXY TCP4 198.18.0.10 198.19.0.20 12345 443\r\n"), []byte("payload"), "198.18.0.10:12345", "198.19.0.20:443"},
		{"v2-tlv", v4, []byte("payload"), "198.18.0.10:12345", "198.19.0.20:443"},
		{"v2-ipv6", v6, []byte("payload"), "[fd00::10]:12345", "[fd00::20]:443"},
		{"unknown", []byte("PROXY UNKNOWN anything ignored\r\n"), []byte("payload"), "pipe", "pipe"},
		{"local", proxyV2(0x11, 0, net.IP{1, 2, 3, 4}, net.IP{5, 6, 7, 8}, nil), []byte("payload"), "pipe", "pipe"},
		{"plain-http", nil, []byte("POST / HTTP/1.1\r\n"), "pipe", "pipe"},
		{"plain-prefix", nil, []byte("PROX! ordinary"), "pipe", "pipe"},
		{"plain-tls", nil, []byte{22, 3, 3, 0, 1, 0}, "pipe", "pipe"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peer, raw := net.Pipe()
			defer peer.Close()
			defer raw.Close()
			conn := AutoProxyConn(raw)
			done := make(chan error, 1)
			go func() {
				for _, b := range tc.header {
					if _, err := peer.Write([]byte{b}); err != nil {
						done <- err
						return
					}
				}
				_, err := peer.Write(tc.payload)
				done <- err
			}()
			if conn.RemoteAddr().String() != tc.source || conn.LocalAddr().String() != tc.destination {
				t.Fatal("incorrect reported endpoints", conn.RemoteAddr(), conn.LocalAddr())
			}
			value := make([]byte, len(tc.payload))
			if _, err := io.ReadFull(conn, value); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(value, tc.payload) {
				t.Fatal("application bytes changed")
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestInvalidAndTruncatedProxyHeaders(t *testing.T) {
	for _, header := range [][]byte{
		[]byte("PROXY TCP6 fd00::10%zone fd00::20 10 443\r\n"),
		[]byte("PROXY TCP4 not-an-ip 198.19.0.20 10 443\r\n"),
		[]byte("PROXY TCP4 198.18.0.10 198.19.0.20 70000 443\r\n"),
		[]byte("PROXY " + strings.Repeat("x", 108)),
		append(append([]byte(nil), proxyV2Magic...), 0x31, 0x11, 0, 0),
		append(append([]byte(nil), proxyV2Magic...), 0x21, 0x12, 0, 0),
		append(append([]byte(nil), proxyV2Magic...), 0x21, 0x11, 0, 12, 1, 2),
	} {
		peer, raw := net.Pipe()
		conn := AutoProxyConn(raw)
		go func() { _, _ = peer.Write(header); peer.Close() }()
		var b [1]byte
		_, err := conn.Read(b[:])
		conn.Close()
		if err == nil {
			t.Fatal("invalid proxy header accepted")
		}
	}
}
func TestProxySniffPreservesEarlierDeadline(t *testing.T) {
	peer, raw := net.Pipe()
	defer peer.Close()
	defer raw.Close()
	conn := &autoProxyConn{Conn: raw}
	if err := conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if _, err := conn.Read(b[:]); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("sniff ignored earlier deadline", err)
	}
	if _, err := raw.Read(b[:]); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("sniff erased the caller's deadline", err)
	}
}
func TestAutomaticProxyAcceptNeverWaitsForHeader(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	wrapped := AutoProxyListener(listener)
	accepted := make(chan net.Conn, 2)
	go func() {
		for range 2 {
			c, e := wrapped.Accept()
			if e == nil {
				accepted <- c
			}
		}
	}()
	first, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	for range 2 {
		select {
		case c := <-accepted:
			c.Close()
		case <-time.After(time.Second):
			t.Fatal("slow header blocked Accept")
		}
	}
}

type notifyReadConn struct {
	net.Conn
	entered chan struct{}
	once    sync.Once
}

func (c *notifyReadConn) Read(p []byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	return c.Conn.Read(p)
}
func TestProxySniffDoesNotRestoreOverConcurrentDeadlineUpdate(t *testing.T) {
	peer, raw := net.Pipe()
	defer peer.Close()
	defer raw.Close()
	entered := make(chan struct{})
	conn := &autoProxyConn{Conn: &notifyReadConn{Conn: raw, entered: entered}}
	result := make(chan error, 1)
	go func() { var b [1]byte; _, err := conn.Read(b[:]); result <- err }()
	<-entered
	if err := conn.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	go func() { var b [1]byte; _, err := raw.Read(b[:]); result <- err }()
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("sniff restored an obsolete read deadline")
	}
}
func TestProxyCoalescedPayloadCopy(t *testing.T) {
	peer, raw := net.Pipe()
	defer peer.Close()
	defer raw.Close()
	payload := bytes.Repeat([]byte("payload after header"), 5000)
	go func() {
		_, _ = peer.Write(append([]byte("PROXY TCP4 198.18.0.10 198.19.0.20 12345 443\r\n"), payload...))
		peer.Close()
	}()
	conn := AutoProxyConn(raw)
	var out bytes.Buffer
	if _, err := io.Copy(&out, conn); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, out.Bytes()) {
		t.Fatal("coalesced payload was lost by the fast copy path")
	}
}
