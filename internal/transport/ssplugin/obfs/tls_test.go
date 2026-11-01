// SPDX-License-Identifier: GPL-3.0-or-later
// Adapted from Polaris; see THIRD_PARTY_NOTICES.md.
package obfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing/common/buf"
)

func TestTLSServerConnReadsFragmentedClient(t *testing.T) {
	first := []byte("first-payload")
	second := bytes.Repeat([]byte("second-payload-"), 128)
	wire := makeTestClientHello(first, "example.com")
	wire = appendTLSRecord(wire, second)
	raw := &obfsTestConn{reader: &chunkReader{reader: bytes.NewReader(wire), maximum: 1}}
	conn := newTLSServerConn(raw)
	decoded, err := io.ReadAll(conn)
	if err != nil || !bytes.Equal(decoded, append(first, second...)) {
		t.Fatalf("ReadAll() length = %d, error = %v", len(decoded), err)
	}
}

func TestTLSServerConnReadResumesAfterTemporaryError(t *testing.T) {
	payload := bytes.Repeat([]byte("temporary-error-"), 64)
	wire := makeTestClientHello(payload, "example.com")
	wire = appendTLSRecord(wire, []byte("tail"))
	for _, interruptAt := range []int{3, tlsFirstClientHeaderSize + len(payload)/2, len(wire) - 3} {
		t.Run(fmt.Sprintf("offset=%d", interruptAt), func(t *testing.T) {
			raw := &obfsTestConn{reader: &interruptReader{data: wire, interruptAt: interruptAt}}
			conn := newTLSServerConn(raw)
			var decoded []byte
			var output [257]byte
			for len(decoded) < len(payload)+len("tail") {
				count, err := conn.Read(output[:])
				decoded = append(decoded, output[:count]...)
				if err != nil && !errors.Is(err, errObfsTestTemporary) {
					t.Fatal(err)
				}
			}
			if !bytes.Equal(decoded, append(payload, []byte("tail")...)) {
				t.Fatalf("decoded length = %d", len(decoded))
			}
		})
	}
}

func TestTLSServerConnValidatesAndSkipsEmptyRecords(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		wire := appendTLSRecord(nil, nil)
		wire = appendTLSRecord(wire, []byte("payload"))
		conn := &tlsServerConn{Conn: &obfsTestConn{reader: bytes.NewReader(wire)}, tailRead: true}
		output := make([]byte, len("payload"))
		count, err := conn.Read(output)
		if err != nil || count != len(output) || string(output) != "payload" {
			t.Fatalf("Read() = %d, %q, %v", count, output, err)
		}
	})
	t.Run("malformed", func(t *testing.T) {
		wire := appendTLSRecord(nil, []byte("payload"))
		wire[0] = 0x16
		conn := &tlsServerConn{Conn: &obfsTestConn{reader: bytes.NewReader(wire)}, tailRead: true}
		_, err := conn.Read(make([]byte, 16))
		if !errors.Is(err, errMalformedTLSObfsRecord) {
			t.Fatalf("Read() error = %v", err)
		}
	})
}

func TestTLSServerConnConcurrentRead(t *testing.T) {
	payload := bytes.Repeat([]byte("concurrent-tls-obfs-"), 4096)
	var wire []byte
	for offset := 0; offset < len(payload); offset += 4096 {
		end := min(offset+4096, len(payload))
		wire = appendTLSRecord(wire, payload[offset:end])
	}
	conn := &tlsServerConn{Conn: &obfsTestConn{reader: bytes.NewReader(wire)}, tailRead: true}
	var readBytes atomic.Int64
	var workers sync.WaitGroup
	workers.Add(4)
	for range 4 {
		go func() {
			defer workers.Done()
			var output [257]byte
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

func TestTLSServerConnConcurrentWrite(t *testing.T) {
	const (
		workers     = 8
		payloadSize = 32
	)
	var wire bytes.Buffer
	conn := newTLSServerConn(&obfsTestConn{writer: &wire})
	var wait sync.WaitGroup
	wait.Add(workers)
	for index := range workers {
		go func() {
			defer wait.Done()
			payload := bytes.Repeat([]byte{byte(index)}, payloadSize)
			if count, err := conn.Write(payload); err != nil || count != len(payload) {
				t.Errorf("Write() = %d, %v", count, err)
			}
		}()
	}
	wait.Wait()
	encoded := wire.Bytes()
	wantLength := tlsServerHelloSize + payloadSize + (workers-1)*(5+payloadSize)
	if len(encoded) != wantLength {
		t.Fatalf("encoded length = %d, want %d", len(encoded), wantLength)
	}
	offset := tlsServerHelloSize + payloadSize
	for index := 1; index < workers; index++ {
		if !bytes.Equal(encoded[offset:offset+3], []byte{0x17, 0x03, 0x03}) ||
			int(binary.BigEndian.Uint16(encoded[offset+3:offset+5])) != payloadSize {
			t.Fatalf("malformed record %d at offset %d", index, offset)
		}
		offset += 5 + payloadSize
	}
}

func TestTLSServerConnWritesCompatibleRecords(t *testing.T) {
	first := []byte("first")
	second := bytes.Repeat([]byte{0x42}, tlsChunkSize+17)
	var wire bytes.Buffer
	conn := newTLSServerConn(&obfsTestConn{writer: &wire})
	if count, err := conn.Write(first); err != nil || count != len(first) {
		t.Fatalf("first Write() = %d, %v", count, err)
	}
	if count, err := conn.Write(second); err != nil || count != len(second) {
		t.Fatalf("second Write() = %d, %v", count, err)
	}
	encoded := wire.Bytes()
	if len(encoded) != tlsServerHelloSize+len(first)+5+tlsChunkSize+5+17 ||
		!bytes.Equal(encoded[:5], []byte{0x16, 0x03, 0x01, 0x00, 0x5b}) ||
		!bytes.Equal(encoded[96:105], []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x16, 0x03, 0x03}) ||
		int(binary.BigEndian.Uint16(encoded[105:107])) != len(first) ||
		!bytes.Equal(encoded[107:107+len(first)], first) {
		t.Fatal("incompatible first TLS obfs response")
	}
	offset := tlsServerHelloSize + len(first)
	if !bytes.Equal(encoded[offset:offset+3], []byte{0x17, 0x03, 0x03}) ||
		int(binary.BigEndian.Uint16(encoded[offset+3:offset+5])) != tlsChunkSize {
		t.Fatal("incompatible application-data record")
	}
}

func TestTLSServerConnRejectsShortWrite(t *testing.T) {
	conn := newTLSServerConn(&obfsTestConn{writer: shortWriter{}})
	if _, err := conn.Write([]byte("payload")); err == nil {
		t.Fatal("Write() unexpectedly succeeded")
	}
}

func FuzzTLSServerConnRead(f *testing.F) {
	f.Add(makeTestClientHello([]byte("payload"), "example.com"))
	f.Add([]byte("invalid"))
	f.Fuzz(func(t *testing.T, wire []byte) {
		conn := newTLSServerConn(&obfsTestConn{reader: bytes.NewReader(wire)})
		_, _ = conn.Read(make([]byte, 256))
	})
}

func BenchmarkTLSServerConnSteadyWrite(b *testing.B) {
	for _, payloadSize := range []int{1200, tlsChunkSize, 64 * 1024} {
		b.Run(fmt.Sprintf("payload=%d", payloadSize), func(b *testing.B) {
			conn := newTLSServerConn(&obfsTestConn{})
			if _, err := conn.Write([]byte{1}); err != nil {
				b.Fatal(err)
			}
			payload := bytes.Repeat([]byte{0x5a}, payloadSize)
			b.ReportAllocs()
			b.SetBytes(int64(payloadSize))
			b.ResetTimer()
			for b.Loop() {
				if _, err := conn.Write(payload); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkLegacyTLSServerConnSteadyWrite(b *testing.B) {
	for _, payloadSize := range []int{1200, tlsChunkSize, 64 * 1024} {
		b.Run(fmt.Sprintf("payload=%d", payloadSize), func(b *testing.B) {
			raw := &obfsTestConn{}
			payload := bytes.Repeat([]byte{0x5a}, payloadSize)
			b.ReportAllocs()
			b.SetBytes(int64(payloadSize))
			for b.Loop() {
				for offset := 0; offset < len(payload); offset += tlsChunkSize {
					end := min(offset+tlsChunkSize, len(payload))
					buffer := buf.NewSize(5 + end - offset)
					header := buffer.Extend(5)
					header[0], header[1], header[2] = 0x17, 0x03, 0x03
					binary.BigEndian.PutUint16(header[3:], uint16(end-offset))
					_, _ = buffer.Write(payload[offset:end])
					_, err := raw.Write(buffer.Bytes())
					buffer.Release()
					if err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}

func appendTLSRecord(destination, payload []byte) []byte {
	destination = append(destination, 0x17, 0x03, 0x03, byte(len(payload)>>8), byte(len(payload)))
	return append(destination, payload...)
}

func makeTestClientHello(payload []byte, host string) []byte {
	recordLength := 212 + len(payload) + len(host)
	buffer := bytes.NewBuffer(make([]byte, 0, recordLength+5))
	buffer.Write([]byte{0x16, 0x03, 0x01, byte(recordLength >> 8), byte(recordLength)})
	buffer.Write([]byte{0x01, byte((recordLength - 4) >> 16), byte((recordLength - 4) >> 8), byte(recordLength - 4), 0x03, 0x03})
	buffer.Write(make([]byte, 32))
	buffer.WriteByte(32)
	buffer.Write(make([]byte, 32))
	buffer.Write([]byte{0x00, 0x38})
	buffer.Write([]byte{
		0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f,
		0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a,
		0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d,
		0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
	})
	buffer.Write([]byte{0x01, 0x00, byte((79 + len(payload) + len(host)) >> 8), byte(79 + len(payload) + len(host))})
	buffer.Write([]byte{0x00, 0x23, byte(len(payload) >> 8), byte(len(payload))})
	buffer.Write(payload)
	buffer.Write([]byte{0x00, 0x00, byte((len(host) + 5) >> 8), byte(len(host) + 5), byte((len(host) + 3) >> 8), byte(len(host) + 3), 0x00, byte(len(host) >> 8), byte(len(host))})
	buffer.WriteString(host)
	buffer.Write(tlsClientHelloTail)
	return buffer.Bytes()
}
