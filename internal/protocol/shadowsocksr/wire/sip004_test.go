// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package shadowsocksr

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"

	ssrcipher "github.com/Ember-Moth/Lunaris/internal/protocol/shadowsocksr/wire/cipher"
)

var integrationSIP004Methods = []string{
	"aes-128-gcm",
	"aes-192-gcm",
	"aes-256-gcm",
	"chacha20-ietf-poly1305",
	"xchacha20-ietf-poly1305",
}

func TestSIP004ServerConnBidirectional(t *testing.T) {
	for _, method := range integrationSIP004Methods {
		t.Run(method, func(t *testing.T) {
			server := newSIP004TestServer(t, method, nil)
			raw, peer := net.Pipe()
			defer peer.Close()
			deadline := time.Now().Add(3 * time.Second)
			_ = raw.SetDeadline(deadline)
			_ = peer.SetDeadline(deadline)
			conn, err := server.WrapConn(raw)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()

			request := bytes.Repeat([]byte("request"), 173)
			clientSalt := deterministicSalt(server.cipher.IVLen())
			clientCipher, err := server.cipher.NewAEADStream(clientSalt)
			if err != nil {
				t.Fatal(err)
			}
			requestWire, err := clientCipher.Seal(append([]byte(nil), clientSalt...), request)
			if err != nil {
				t.Fatal(err)
			}
			writeDone := make(chan error, 1)
			go func() {
				_, writeErr := peer.Write(requestWire)
				writeDone <- writeErr
			}()
			decodedRequest := make([]byte, len(request))
			if _, err = io.ReadFull(conn, decodedRequest); err != nil {
				t.Fatal(err)
			}
			if err = <-writeDone; err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(decodedRequest, request) {
				t.Fatal("decoded request differs")
			}
			if userID, authenticated := conn.UserID(); !authenticated || userID != [4]byte{1} {
				t.Fatalf("user=%v authenticated=%v", userID, authenticated)
			}

			response := bytes.Repeat([]byte("response"), 97)
			responseSize := server.cipher.IVLen() + 18 + len(response) + 16
			responseWire := make([]byte, responseSize)
			writeDone = make(chan error, 1)
			go func() {
				_, writeErr := conn.Write(response)
				writeDone <- writeErr
			}()
			if _, err = io.ReadFull(peer, responseWire); err != nil {
				t.Fatal(err)
			}
			if err = <-writeDone; err != nil {
				t.Fatal(err)
			}
			serverSalt := responseWire[:server.cipher.IVLen()]
			responseCipher, err := server.cipher.NewAEADStream(serverSalt)
			if err != nil {
				t.Fatal(err)
			}
			decodedResponse, err := responseCipher.Open(nil, responseWire[len(serverSalt):])
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(decodedResponse, response) {
				t.Fatal("decoded response differs")
			}

			secondResponse := bytes.Repeat([]byte("second"), 41)
			secondWire := make([]byte, 18+len(secondResponse)+16)
			writeDone = make(chan error, 1)
			go func() {
				_, writeErr := conn.Write(secondResponse)
				writeDone <- writeErr
			}()
			if _, err = io.ReadFull(peer, secondWire); err != nil {
				t.Fatal(err)
			}
			if err = <-writeDone; err != nil {
				t.Fatal(err)
			}
			decodedResponse, err = responseCipher.Open(nil, secondWire)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(decodedResponse, secondResponse) {
				t.Fatal("decoded second response differs")
			}
		})
	}
}

func TestSIP004PacketCodecRoundTrip(t *testing.T) {
	for _, method := range integrationSIP004Methods {
		t.Run(method, func(t *testing.T) {
			server := newSIP004TestServer(t, method, nil)
			codec, err := server.NewPacketCodec()
			if err != nil {
				t.Fatal(err)
			}
			payload := bytes.Repeat([]byte("udp"), 211)
			packet := buf.NewSize(len(payload) + 256)
			defer packet.Release()
			_, _ = packet.Write(payload)
			encoded, err := codec.Encode(packet, [4]byte{1})
			if err != nil {
				t.Fatal(err)
			}
			if encoded != packet {
				defer encoded.Release()
			}
			if userID, decodeErr := codec.Decode(encoded); decodeErr != nil {
				t.Fatal(decodeErr)
			} else if userID != [4]byte{1} {
				t.Fatalf("user ID = %v", userID)
			}
			if !bytes.Equal(encoded.Bytes(), payload) {
				t.Fatal("decoded packet differs")
			}
		})
	}
}

func TestSIP004TCPRejectsReplayedSalt(t *testing.T) {
	replayState := NewReplayState(nil)
	server := newSIP004TestServer(t, "aes-128-gcm", replayState)
	payload := []byte("authenticated request")
	salt := deterministicSalt(server.cipher.IVLen())
	encoder, err := server.cipher.NewAEADStream(salt)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := encoder.Seal(append([]byte(nil), salt...), payload)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := readSIP004Request(server, wire, len(payload)); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(decoded, payload) {
		t.Fatal("first request differs")
	}
	if _, err = readSIP004Request(server, wire, len(payload)); !errors.Is(err, ssrcipher.ErrReplay) {
		t.Fatalf("replay error = %v", err)
	}
}

func TestSIP004TCPDoesNotCacheUnauthenticatedSalt(t *testing.T) {
	server := newSIP004TestServer(t, "aes-128-gcm", NewReplayState(nil))
	payload := []byte("authenticated request")
	salt := deterministicSalt(server.cipher.IVLen())
	encoder, err := server.cipher.NewAEADStream(salt)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := encoder.Seal(append([]byte(nil), salt...), payload)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Clone(wire)
	tampered[len(tampered)-1] ^= 1
	if _, err = readSIP004Request(server, tampered, len(payload)); !errors.Is(err, ssrcipher.ErrAuthentication) {
		t.Fatalf("tampered request error = %v", err)
	}
	if decoded, validErr := readSIP004Request(server, wire, len(payload)); validErr != nil {
		t.Fatalf("valid request after tamper: %v", validErr)
	} else if !bytes.Equal(decoded, payload) {
		t.Fatal("valid request differs")
	}
}

func TestSIP004ProtocolAndObfsConstructionMatrix(t *testing.T) {
	protocols := []string{
		"origin", "verify_simple", "verify_sha1", "auth_simple", "auth_sha1", "auth_sha1_v2", "auth_sha1_v4",
		"auth_aes128_md5", "auth_aes128_sha1", "auth_chain_a", "auth_chain_b", "auth_chain_c", "auth_chain_d",
		"auth_chain_e", "auth_chain_f",
	}
	obfuscations := []string{"plain", "http_simple", "http_post", "tls1.0_session_auth", "tls1.2_ticket_auth", "tls1.2_ticket_fastauth"}
	for _, method := range integrationSIP004Methods {
		for _, protocolName := range protocols {
			users := map[[4]byte]string{{1}: "user-password"}
			if _, err := NewServer(ServerConfig{Method: method, Password: "server-password", Protocol: protocolName,
				Obfs: "plain", Host: "127.0.0.1", Port: 8388}, users); err != nil {
				t.Fatalf("%s/%s: %v", method, protocolName, err)
			}
		}
		for _, obfsName := range obfuscations {
			if _, err := NewServer(ServerConfig{Method: method, Password: "server-password", Protocol: "origin",
				Obfs: obfsName, Host: "127.0.0.1", Port: 8388}, map[[4]byte]string{{1}: "user-password"}); err != nil {
				t.Fatalf("%s/%s: %v", method, obfsName, err)
			}
		}
	}
}

func newSIP004TestServer(t *testing.T, method string, replayState *ReplayState) *Server {
	t.Helper()
	server, err := NewServer(ServerConfig{Method: method, Password: "server-password", Protocol: "origin",
		Obfs: "plain", Host: "127.0.0.1", Port: 8388, ReplayState: replayState}, map[[4]byte]string{{1}: "user-password"})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func readSIP004Request(server *Server, wire []byte, size int) ([]byte, error) {
	raw, peer := net.Pipe()
	deadline := time.Now().Add(3 * time.Second)
	_ = raw.SetDeadline(deadline)
	_ = peer.SetDeadline(deadline)
	conn, err := server.WrapConn(raw)
	if err != nil {
		peer.Close()
		return nil, err
	}
	defer conn.Close()
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := peer.Write(wire)
		writeDone <- writeErr
		peer.Close()
	}()
	decoded := make([]byte, size)
	_, err = io.ReadFull(conn, decoded)
	writeErr := <-writeDone
	if err == nil {
		err = writeErr
	}
	return decoded, err
}

func deterministicSalt(length int) []byte {
	salt := make([]byte, length)
	for index := range salt {
		salt[index] = byte(index*19 + 5)
	}
	return salt
}
