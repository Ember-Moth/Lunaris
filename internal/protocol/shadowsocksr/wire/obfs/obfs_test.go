// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package obfs

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/protocol/shadowsocksr/wire/replay"
)

var obfsBenchmarkSink []byte

func TestSHA1HMACMatchesStandardLibrary(t *testing.T) {
	dataFirst := bytes.Repeat([]byte{0xa5}, 4093)
	dataSecond := bytes.Repeat([]byte{0x5a}, 4099)
	worker := newSHA1HMAC()
	for _, keyLength := range []int{0, 1, 20, 63, 64, 65, 100} {
		t.Run(fmt.Sprintf("key=%d", keyLength), func(t *testing.T) {
			key := bytes.Repeat([]byte{byte(keyLength + 1)}, keyLength)
			standard := hmac.New(sha1.New, key)
			_, _ = standard.Write(dataFirst)
			_, _ = standard.Write(dataSecond)
			want := standard.Sum(nil)
			split := len(key) / 2
			got := worker.sum(key[:split], key[split:], dataFirst, dataSecond)
			if !bytes.Equal(got, want) {
				t.Fatalf("HMAC mismatch: got %x, want %x", got, want)
			}
		})
	}
}

func TestHTTPDecodeFragmented(t *testing.T) {
	now := func() time.Time { return time.Unix(1_700_000_000, 0) }
	want := append([]byte{1, 2, 3, 4, 'h', 'i'}, "tail"...)
	for _, test := range []struct {
		name, method string
	}{
		{"http_simple", "GET"},
		{"http_post", "POST"},
	} {
		t.Run(test.name, func(t *testing.T) {
			definition, err := New(Config{Name: test.name, Param: "example.com,cdn.example#ignored", Now: now})
			if err != nil {
				t.Fatal(err)
			}
			wire := []byte(test.method + " /%01%02%03%04%68%69 HTTP/1.1\r\nHost: example.com:443\r\nUser-Agent: test\r\n\r\ntail")
			for _, chunkSize := range []int{1, 2, 4, 7, len(wire)} {
				t.Run(fmt.Sprintf("chunk=%d", chunkSize), func(t *testing.T) {
					decoded, replied := decodeFragments(t, definition.NewStream(), wire, chunkSize)
					if !bytes.Equal(decoded, want) || replied {
						t.Fatalf("decoded=%x reply=%v, want=%x", decoded, replied, want)
					}
				})
			}
		})
	}
}

func TestHTTPRejectsUnknownHostAndOversizedHeader(t *testing.T) {
	definition, err := New(Config{Name: "http_post", Param: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = definition.NewStream().Decode([]byte("POST /%01%02%03%04 HTTP/1.1\r\nHost: invalid.example\r\n\r\n")); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("unknown host error=%v", err)
	}
	oversized := append([]byte("GET /%01%02%03%04 HTTP/1.1\r\nX: "), bytes.Repeat([]byte{'a'}, maxHTTPHeader)...)
	if _, _, _, err = definition.NewStream().Decode(oversized); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("oversized header error=%v", err)
	}
}

func TestHTTPEncodeResponseHeader(t *testing.T) {
	now := func() time.Time { return time.Date(2023, time.November, 14, 22, 13, 20, 0, time.UTC) }
	definition, err := New(Config{Name: "http_simple", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	stream := definition.NewStream()
	first, err := stream.Encode(nil, []byte("first"))
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Encoding: gzip\r\nContent-Type: text/html\r\nDate: Tue, 14 Nov 2023 22:13:20 GMT\r\nServer: nginx\r\nVary: Accept-Encoding\r\n\r\nfirst")
	if !bytes.Equal(first, want) {
		t.Fatalf("response mismatch:\n%s", first)
	}
	second, err := stream.Encode(nil, []byte("second"))
	if err != nil || !bytes.Equal(second, []byte("second")) {
		t.Fatalf("second response=%q error=%v", second, err)
	}
}

func TestTLS10DecodeFragmented(t *testing.T) {
	config := testObfsConfig("tls1.0_session_auth")
	session := bytes.Repeat([]byte{0x35}, 32)
	builder := &tls10Stream{config: config}
	hello, err := builder.buildHello(0x01, session)
	if err != nil {
		t.Fatal(err)
	}
	finished, err := builder.buildFinished(session, nil)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("payload-"), 32)
	wire := append(append(append([]byte(nil), hello...), finished...), payload...)
	for _, chunkSize := range []int{1, 3, 31, len(wire)} {
		t.Run(fmt.Sprintf("chunk=%d", chunkSize), func(t *testing.T) {
			definition, newErr := New(testObfsConfig("tls1.0_session_auth"))
			if newErr != nil {
				t.Fatal(newErr)
			}
			decoded, replied := decodeFragments(t, definition.NewStream(), wire, chunkSize)
			if !bytes.Equal(decoded, payload) || !replied {
				t.Fatalf("decoded=%x reply=%v", decoded, replied)
			}
		})
	}
}

func TestTLSTicketDecodeFragmented(t *testing.T) {
	payload := bytes.Repeat([]byte("ticket-payload-"), 400)
	wire := append(testTLSTicketClientHandshake(t, testObfsConfig("tls1.2_ticket_auth")), tlsApplicationRecords(payload, 2048)...)
	for _, chunkSize := range []int{1, 5, 37, 2048, len(wire)} {
		t.Run(fmt.Sprintf("chunk=%d", chunkSize), func(t *testing.T) {
			definition, err := New(testObfsConfig("tls1.2_ticket_auth"))
			if err != nil {
				t.Fatal(err)
			}
			decoded, replied := decodeFragments(t, definition.NewStream(), wire, chunkSize)
			if !bytes.Equal(decoded, payload) || !replied {
				t.Fatalf("decoded length=%d reply=%v, want=%d", len(decoded), replied, len(payload))
			}
		})
	}
}

func TestTLSTicketRejectsOversizedFinishedRecordImmediately(t *testing.T) {
	stream := &tlsTicketStream{config: testObfsConfig("tls1.2_ticket_auth"), state: tlsTicketNeedFinished}
	header := []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x16, 0x03, 0x03, 0xff, 0xff}
	if _, _, _, err := stream.Decode(header); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("oversized Finished error=%v", err)
	}
}

func TestTLSTicketEncodeApplicationRecords(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5a}, 5000)
	stream := &tlsTicketStream{config: testObfsConfig("tls1.2_ticket_fastauth"), state: tlsTicketStreaming, wroteHead: true}
	wire, err := stream.Encode(nil, payload)
	if err != nil {
		t.Fatal(err)
	}
	decoded, _, _, err := (&tlsTicketStream{state: tlsTicketStreaming}).Decode(wire)
	if err != nil || !bytes.Equal(decoded, payload) {
		t.Fatalf("round trip length=%d error=%v", len(decoded), err)
	}
}

func TestTLSHandshakeResponsesAuthenticate(t *testing.T) {
	clientID := bytes.Repeat([]byte{0x53}, 32)
	payload := bytes.Repeat([]byte{0x5a}, 5000)

	t.Run("tls1.0_session_auth", func(t *testing.T) {
		config := testObfsConfig("tls1.0_session_auth")
		stream := &tls10Stream{config: config, state: tls10Streaming, clientID: clientID}
		wire, err := stream.Encode(nil, payload)
		if err != nil {
			t.Fatal(err)
		}
		helloLength := int(binary.BigEndian.Uint16(wire[3:5])) + 5
		session, verify, err := parseTLS10Hello(wire[:helloLength], 0x02)
		if err != nil || !bytes.Equal(session, clientID) {
			t.Fatalf("server hello session=%x error=%v", session, err)
		}
		macWorker := newSHA1HMAC()
		if !validSHA1(macWorker.sum(config.ServerKey, session, verify[:22], nil), verify[22:32]) {
			t.Fatal("server hello MAC mismatch")
		}
		finished := wire[helloLength : helloLength+43]
		if !validSHA1(macWorker.sum(config.ServerKey, session, wire[:helloLength], finished[:33]), finished[33:43]) {
			t.Fatal("server Finished MAC mismatch")
		}
		if !bytes.Equal(wire[helloLength+43:], payload) {
			t.Fatal("TLS1.0 response payload mismatch")
		}
	})

	t.Run("tls1.2_ticket_auth", func(t *testing.T) {
		config := testObfsConfig("tls1.2_ticket_auth")
		stream := &tlsTicketStream{config: config, state: tlsTicketStreaming, clientID: clientID}
		wire, err := stream.Encode(nil, payload)
		if err != nil {
			t.Fatal(err)
		}
		helloLength := int(binary.BigEndian.Uint16(wire[3:5])) + 5
		hello := wire[5:helloLength]
		if len(hello) < 39 || hello[0] != 0x02 || !bytes.Equal(hello[4:6], []byte{0x03, 0x03}) {
			t.Fatal("invalid TLS1.2 server hello")
		}
		verify := hello[6:38]
		sessionLength := int(hello[38])
		session := hello[39 : 39+sessionLength]
		macWorker := newSHA1HMAC()
		if !bytes.Equal(session, clientID) || !validSHA1(macWorker.sum(config.ServerKey, session, verify[:22], nil), verify[22:32]) {
			t.Fatal("TLS1.2 server hello authentication mismatch")
		}
		finishedEnd := helloLength + 43
		if !validSHA1(macWorker.sum(config.ServerKey, session, wire[:finishedEnd-10], nil), wire[finishedEnd-10:finishedEnd]) {
			t.Fatal("TLS1.2 server Finished MAC mismatch")
		}
		decoded, decrypt, _, err := (&tlsTicketStream{state: tlsTicketStreaming}).Decode(wire[finishedEnd:])
		if err != nil || !decrypt || !bytes.Equal(decoded, payload) {
			t.Fatalf("TLS1.2 response payload length=%d error=%v", len(decoded), err)
		}
	})
}

func FuzzHTTPDecode(f *testing.F) {
	f.Add([]byte("GET /%01%02%03%04 HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	f.Add([]byte("invalid"))
	f.Fuzz(func(t *testing.T, input []byte) {
		definition, err := New(Config{Name: "http_simple"})
		if err != nil {
			t.Fatal(err)
		}
		_, _, _, _ = definition.NewStream().Decode(input)
	})
}

func FuzzTLSTicketDecode(f *testing.F) {
	f.Add([]byte{0x16, 0x03, 0x01, 0, 0})
	f.Add([]byte("invalid"))
	f.Fuzz(func(t *testing.T, input []byte) {
		definition, err := New(testObfsConfig("tls1.2_ticket_auth"))
		if err != nil {
			t.Fatal(err)
		}
		_, _, _, _ = definition.NewStream().Decode(input)
	})
}

func BenchmarkTLSTicketApplicationDecode(b *testing.B) {
	for _, payloadSize := range []int{1200, 8 * 1024} {
		b.Run(fmt.Sprintf("payload=%d", payloadSize), func(b *testing.B) {
			payload := bytes.Repeat([]byte{0x5a}, payloadSize)
			wire := tlsApplicationRecords(payload, 2048)
			stream := &tlsTicketStream{state: tlsTicketStreaming}
			b.ReportAllocs()
			b.SetBytes(int64(payloadSize))
			for b.Loop() {
				decoded, decrypt, _, err := stream.Decode(wire)
				if err != nil || !decrypt || len(decoded) != len(payload) {
					b.Fatalf("decoded=%d decrypt=%v error=%v", len(decoded), decrypt, err)
				}
				obfsBenchmarkSink = decoded
			}
		})
	}
}

func BenchmarkHTTPHandshakeDecode(b *testing.B) {
	definition, err := New(Config{Name: "http_simple", Param: "example.com,cdn.example"})
	if err != nil {
		b.Fatal(err)
	}
	wire := []byte("GET /%01%02%03%04%68%69 HTTP/1.1\r\nHost: example.com:443\r\nUser-Agent: test\r\n\r\ntail")
	b.ReportAllocs()
	b.SetBytes(int64(len(wire)))
	for b.Loop() {
		decoded, decrypt, _, decodeErr := definition.NewStream().Decode(wire)
		if decodeErr != nil || !decrypt {
			b.Fatal(decodeErr)
		}
		obfsBenchmarkSink = decoded
	}
}

func BenchmarkTLSHandshakeEncode(b *testing.B) {
	for _, name := range []string{"tls1.0_session_auth", "tls1.2_ticket_auth"} {
		b.Run(name, func(b *testing.B) {
			config := testObfsConfig(name)
			clientID := bytes.Repeat([]byte{0x53}, 32)
			payload := bytes.Repeat([]byte{0x5a}, 1200)
			b.ReportAllocs()
			b.SetBytes(int64(len(payload)))
			for b.Loop() {
				var stream Stream
				if name == "tls1.0_session_auth" {
					stream = &tls10Stream{config: config, state: tls10Streaming, clientID: clientID}
				} else {
					stream = &tlsTicketStream{config: config, state: tlsTicketStreaming, clientID: clientID}
				}
				encoded, err := stream.Encode(nil, payload)
				if err != nil {
					b.Fatal(err)
				}
				obfsBenchmarkSink = encoded
			}
		})
	}
}

func decodeFragments(t *testing.T, stream Stream, wire []byte, chunkSize int) ([]byte, bool) {
	t.Helper()
	var decoded []byte
	var replied bool
	for offset := 0; offset < len(wire); offset += chunkSize {
		end := min(offset+chunkSize, len(wire))
		data, decrypt, reply, err := stream.Decode(wire[offset:end])
		if err != nil {
			t.Fatalf("Decode(%d:%d): %v", offset, end, err)
		}
		replied = replied || reply
		if decrypt {
			decoded = append(decoded, data...)
		}
	}
	return decoded, replied
}

func testObfsConfig(name string) Config {
	now := func() time.Time { return time.Unix(1_700_000_000, 0) }
	return Config{
		Name: name, ServerKey: []byte("server-key-16byt"), Now: now,
		Replay: replay.NewCache(now, 1024),
	}
}

func testTLSTicketClientHandshake(t *testing.T, config Config) []byte {
	t.Helper()
	session := bytes.Repeat([]byte{0x53}, 32)
	var verify [32]byte
	binary.BigEndian.PutUint32(verify[:4], uint32(config.Now().Unix()))
	if _, err := rand.Read(verify[4:22]); err != nil {
		t.Fatal(err)
	}
	macWorker := newSHA1HMAC()
	copy(verify[22:], macWorker.sum(config.ServerKey, session, verify[:22], nil))
	body := make([]byte, 0, 4+2+len(verify)+1+len(session))
	body = append(body, 0x01, 0, 0, 0, 0x03, 0x03)
	body = append(body, verify[:]...)
	body = append(body, byte(len(session)))
	body = append(body, session...)
	binary.BigEndian.PutUint16(body[2:4], uint16(len(body)-4))
	hello := []byte{0x16, 0x03, 0x01, 0, 0}
	binary.BigEndian.PutUint16(hello[3:5], uint16(len(body)))
	hello = append(hello, body...)
	finished := []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x16, 0x03, 0x03, 0x00, 0x20}
	finished = append(finished, bytes.Repeat([]byte{0xa5}, 22)...)
	mac := macWorker.sum(config.ServerKey, session, finished, nil)
	finished = append(finished, mac[:10]...)
	return append(hello, finished...)
}

func tlsApplicationRecords(payload []byte, recordSize int) []byte {
	result := make([]byte, 0, len(payload)+(len(payload)+recordSize-1)/recordSize*5)
	for len(payload) > 0 {
		length := min(len(payload), recordSize)
		result = append(result, 0x17, 0x03, 0x03, byte(length>>8), byte(length))
		result = append(result, payload[:length]...)
		payload = payload[length:]
	}
	return result
}

func TestTLSTicketLargeInitialApplicationRecord(t *testing.T) {
	payload := bytes.Repeat([]byte("initial-data"), 5000)
	config := testObfsConfig("tls1.2_ticket_auth")
	wire := append(testTLSTicketClientHandshake(t, config), tlsApplicationRecords(payload, len(payload))...)
	for _, size := range []int{1, 8192, len(wire)} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			definition, err := New(testObfsConfig("tls1.2_ticket_auth"))
			if err != nil {
				t.Fatal(err)
			}
			got, _ := decodeFragments(t, definition.NewStream(), wire, size)
			if !bytes.Equal(got, payload) {
				t.Fatal("large application record changed")
			}
		})
	}
}

func TestTLSTicketOutputCanBeDecryptedInPlace(t *testing.T) {
	payload := bytes.Repeat([]byte("ciphertext"), 6000)
	wire := tlsApplicationRecords(payload, 1379)
	for _, size := range []int{7, 8192, 1300} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			stream := &tlsTicketStream{state: tlsTicketStreaming}
			scratch := make([]byte, size)
			var got []byte
			for offset := 0; offset < len(wire); {
				n := copy(scratch, wire[offset:])
				offset += n
				out, _, _, err := stream.Decode(scratch[:n])
				if err != nil {
					t.Fatal(err)
				}
				got = append(got, out...)
				for i := range out {
					out[i] ^= 0xff
				}
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("borrowed receive storage was overwritten")
			}
		})
	}
}
