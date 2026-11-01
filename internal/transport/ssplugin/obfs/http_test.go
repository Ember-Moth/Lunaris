// SPDX-License-Identifier: GPL-3.0-or-later
// Adapted from Polaris; see THIRD_PARTY_NOTICES.md.
package obfs

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestHTTPServerConnUnwrapsAndWrapsPayload(t *testing.T) {
	serverRaw, client := net.Pipe()
	defer func() { _ = client.Close() }()
	server := Wrap(Config{Mode: "http"}, serverRaw)
	defer func() { _ = server.Close() }()

	readResult := make(chan string, 1)
	go func() {
		payload := make([]byte, 4)
		_, err := io.ReadFull(server, payload)
		if err != nil {
			readResult <- "error: " + err.Error()
			return
		}
		readResult <- string(payload)
	}()
	if _, err := io.WriteString(client, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\n\r\nping"); err != nil {
		t.Fatal(err)
	}
	if got := <-readResult; got != "ping" {
		t.Fatalf("Read() = %q", got)
	}

	go func() { _, _ = server.Write([]byte("pong")) }()
	reader := bufio.NewReader(client)
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "101 Switching Protocols") {
		t.Fatalf("status = %q", status)
	}
	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			t.Fatal(readErr)
		}
		if line == "\r\n" {
			break
		}
	}
	payload := make([]byte, 4)
	if _, err := io.ReadFull(reader, payload); err != nil {
		t.Fatal(err)
	}
	if string(payload) != "pong" {
		t.Fatalf("response payload = %q", payload)
	}
}

func TestHTTPServerConnRejectsOversizedHeader(t *testing.T) {
	raw := &obfsTestConn{reader: bytes.NewReader(bytes.Repeat([]byte{'x'}, maxHTTPObfsHeader))}
	conn := Wrap(Config{Mode: "http"}, raw)
	_, err := conn.Read(make([]byte, 1))
	if !errors.Is(err, errHTTPObfsHeaderTooLarge) {
		t.Fatalf("Read() error = %v", err)
	}
}

func TestHTTPServerConnReadResumesAfterTemporaryError(t *testing.T) {
	payload := []byte("payload-after-temporary-error")
	wire := append([]byte("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive, Upgrade\r\nContent-Length: 29\r\n\r\n"), payload...)
	raw := &obfsTestConn{reader: &interruptReader{data: wire, interruptAt: 23}}
	conn := Wrap(Config{Mode: "http"}, raw)
	output := make([]byte, len(payload))
	if _, err := conn.Read(output); !errors.Is(err, errObfsTestTemporary) {
		t.Fatalf("first Read() error = %v", err)
	}
	count, err := io.ReadFull(conn, output)
	if err != nil || count != len(payload) || !bytes.Equal(output, payload) {
		t.Fatalf("ReadFull() = %d, %q, %v", count, output, err)
	}
}

func TestHTTPServerConnConcurrentRead(t *testing.T) {
	payload := bytes.Repeat([]byte("concurrent-http-obfs-"), 4096)
	wire := append([]byte("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\n\r\n"), payload...)
	conn := Wrap(Config{Mode: "http"}, &obfsTestConn{reader: bytes.NewReader(wire)})
	var readBytes atomic.Int64
	var workers sync.WaitGroup
	workers.Add(4)
	for range 4 {
		go func() {
			defer workers.Done()
			var output [127]byte
			for {
				count, err := conn.Read(output[:])
				readBytes.Add(int64(count))
				if err != nil {
					if !errors.Is(err, io.EOF) {
						t.Errorf("Read(): %v", err)
					}
					return
				}
			}
		}()
	}
	workers.Wait()
	if got := readBytes.Load(); got != int64(len(payload)) {
		t.Fatalf("read %d bytes, want %d", got, len(payload))
	}
}

func TestHTTPServerConnConcurrentWrite(t *testing.T) {
	var wire bytes.Buffer
	conn := Wrap(Config{Mode: "http"}, &obfsTestConn{writer: &wire})
	var workers sync.WaitGroup
	workers.Add(8)
	for range 8 {
		go func() {
			defer workers.Done()
			if count, err := conn.Write([]byte{'x'}); err != nil || count != 1 {
				t.Errorf("Write() = %d, %v", count, err)
			}
		}()
	}
	workers.Wait()
	encoded := wire.Bytes()
	if bytes.Count(encoded, []byte("HTTP/1.1 101 Switching Protocols")) != 1 {
		t.Fatalf("response header count = %d", bytes.Count(encoded, []byte("HTTP/1.1 101 Switching Protocols")))
	}
	headerEnd := bytes.Index(encoded, []byte("\r\n\r\n"))
	if headerEnd < 0 || len(encoded)-(headerEnd+4) != 8 {
		t.Fatalf("encoded response length = %d, header end = %d", len(encoded), headerEnd)
	}
}

func TestHTTPServerConnRejectsShortWrite(t *testing.T) {
	conn := Wrap(Config{Mode: "http"}, &obfsTestConn{writer: shortWriter{}})
	if _, err := conn.Write([]byte("payload")); err == nil {
		t.Fatal("Write() unexpectedly succeeded")
	}
}

func FuzzHTTPServerConnRead(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\n\r\npayload"))
	f.Add([]byte("invalid"))
	f.Fuzz(func(t *testing.T, wire []byte) {
		conn := Wrap(Config{Mode: "http"}, &obfsTestConn{reader: bytes.NewReader(wire)})
		_, _ = conn.Read(make([]byte, 256))
	})
}
