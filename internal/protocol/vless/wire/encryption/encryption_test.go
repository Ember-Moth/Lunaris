// SPDX-License-Identifier: MPL-2.0
// Adapted from Polaris; see THIRD_PARTY_NOTICES.md.
package encryption

import (
	"bytes"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func TestHandshakeRoundTripModes(t *testing.T) {
	for _, mode := range []string{"native", "xorpub", "random"} {
		t.Run(mode, func(t *testing.T) {
			serverConfig, clientConfig := x25519Configs(t, mode, "1rtt")
			server := mustServer(t, serverConfig)
			defer server.Close()
			client := mustClient(t, clientConfig)
			serverConn, clientConn := handshakePair(t, server, client)
			defer serverConn.Close()
			defer clientConn.Close()
			payload := make([]byte, 20000)
			if _, err := io.ReadFull(rand.Reader, payload); err != nil {
				t.Fatal(err)
			}
			roundTrip(t, serverConn, clientConn, payload)
		})
	}
}

func TestHandshakeMLKEMAuthentication(t *testing.T) {
	privateKey, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	private := base64.RawURLEncoding.EncodeToString(privateKey.Bytes())
	public := base64.RawURLEncoding.EncodeToString(privateKey.EncapsulationKey().Bytes())
	server := mustServer(t, fmt.Sprintf("%s.native.600s.100-35-35.%s", Method, private))
	defer server.Close()
	client := mustClient(t, fmt.Sprintf("%s.native.1rtt.100-35-35.%s", Method, public))
	serverConn, clientConn := handshakePair(t, server, client)
	defer serverConn.Close()
	defer clientConn.Close()
	roundTrip(t, serverConn, clientConn, []byte("post-quantum-authentication"))
}

func TestZeroRTTResumption(t *testing.T) {
	serverConfig, clientConfig := x25519Configs(t, "native", "0rtt")
	server := mustServer(t, serverConfig)
	defer server.Close()
	client := mustClient(t, clientConfig)

	firstServer, firstClient := handshakePair(t, server, client)
	roundTrip(t, firstServer, firstClient, []byte("establish-ticket"))
	_ = firstServer.Close()
	_ = firstClient.Close()

	listener, address := listenLocal(t)
	defer listener.Close()
	serverResult := make(chan handshakeResult, 1)
	go acceptHandshake(listener, server, serverResult)
	rawClient, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = rawClient.SetDeadline(time.Now().Add(5 * time.Second))
	secondClient, err := client.Handshake(rawClient)
	if err != nil {
		t.Fatalf("resume client: %v", err)
	}
	writeResult := make(chan error, 1)
	go func() {
		_, writeErr := secondClient.Write([]byte("zero-rtt"))
		writeResult <- writeErr
	}()
	result := <-serverResult
	if result.err != nil {
		t.Fatalf("resume server: %v", result.err)
	}
	var received [8]byte
	if _, err := io.ReadFull(result.conn, received[:]); err != nil {
		t.Fatal(err)
	}
	if err := <-writeResult; err != nil {
		t.Fatal(err)
	}
	if string(received[:]) != "zero-rtt" {
		t.Fatalf("received %q", received[:])
	}
	_ = result.conn.Close()
	_ = secondClient.Close()
}

func TestZeroRTTClientHelloUsesMinimalBuffer(t *testing.T) {
	_, clientConfig := x25519Configs(t, "native", "0rtt")
	client := mustClient(t, clientConfig)
	client.RWLock.Lock()
	client.Expire = time.Now().Add(time.Minute)
	client.PfsKey = make([]byte, 64)
	client.Ticket = make([]byte, 16)
	client.RWLock.Unlock()
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	conn, err := client.Handshake(local)
	if err != nil {
		t.Fatal(err)
	}
	want := 16 + client.RelaysLength + 18 + 32
	if len(conn.PreWrite) != want {
		t.Fatalf("0-RTT ClientHello length = %d, want %d", len(conn.PreWrite), want)
	}
}

func TestExpireSessionsCatchesUpAcrossSkippedBuckets(t *testing.T) {
	var first, second, future [16]byte
	first[0], second[0], future[0] = 1, 2, 3
	server := &ServerInstance{
		Lasts:    map[int64][16]byte{10: first, 11: second, 13: future},
		Tickets:  [][16]byte{first, second, future},
		Sessions: map[[16]byte]*ServerSession{first: {}, second: {}, future: {}},
	}
	server.expireSessions(11)
	if len(server.Lasts) != 1 || server.Lasts[13] != future {
		t.Fatalf("remaining expiry buckets = %v", server.Lasts)
	}
	if len(server.Tickets) != 1 || server.Tickets[0] != future {
		t.Fatalf("remaining tickets = %v", server.Tickets)
	}
	if len(server.Sessions) != 1 || server.Sessions[future] == nil {
		t.Fatalf("remaining sessions = %v", server.Sessions)
	}
}

func TestXorConnWriteDoesNotMutateInput(t *testing.T) {
	transport := new(recordConn)
	conn := NewXorConn(transport, NewCTR([]byte("key"), make([]byte, 16)), nil, 0, 0)
	payload := make([]byte, 8192)
	EncodeHeader(payload, len(payload)-5)
	for index := 5; index < len(payload); index++ {
		payload[index] = byte(index)
	}
	original := append([]byte(nil), payload...)
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, original) {
		t.Fatal("XorConn.Write mutated the caller's buffer")
	}
	if bytes.Equal(transport.Bytes(), original) {
		t.Fatal("XorConn.Write did not transform the TLS record header")
	}
}

func TestConfigRejectsUnsafeBounds(t *testing.T) {
	private, public := x25519KeyPair(t)
	privateEncoded := base64.RawURLEncoding.EncodeToString(private)
	publicEncoded := base64.RawURLEncoding.EncodeToString(public)
	if _, err := ParseServerConfig(fmt.Sprintf("%s.native.70000s.%s", Method, privateEncoded)); err == nil {
		t.Fatal("server ticket overflow accepted")
	}
	for _, raw := range []string{
		fmt.Sprintf("%s.native.70000s.%s", Method, publicEncoded),
		fmt.Sprintf("%s.native.1rtt.100-35-35.50--1-1.%s", Method, publicEncoded),
		fmt.Sprintf("%s.native.bad.%s", Method, publicEncoded),
	} {
		if _, err := ParseClientConfig(raw); err == nil {
			t.Fatalf("ParseClientConfig(%q) succeeded", raw)
		}
	}
}

func x25519Configs(t *testing.T, mode, rtt string) (string, string) {
	t.Helper()
	private, public := x25519KeyPair(t)
	server := fmt.Sprintf("%s.%s.600s.100-35-35.%s", Method, mode, base64.RawURLEncoding.EncodeToString(private))
	client := fmt.Sprintf("%s.%s.%s.100-35-35.%s", Method, mode, rtt, base64.RawURLEncoding.EncodeToString(public))
	return server, client
}

func x25519KeyPair(t *testing.T) ([]byte, []byte) {
	t.Helper()
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return private.Bytes(), private.PublicKey().Bytes()
}

func mustServer(t *testing.T, raw string) *ServerInstance {
	t.Helper()
	config, err := ParseServerConfig(raw)
	if err != nil {
		t.Fatalf("parse server config: %v", err)
	}
	server, err := config.NewInstance()
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	return server
}

func mustClient(t *testing.T, raw string) *ClientInstance {
	t.Helper()
	config, err := ParseClientConfig(raw)
	if err != nil {
		t.Fatalf("parse client config: %v", err)
	}
	client, err := config.NewInstance()
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	return client
}

type handshakeResult struct {
	conn *CommonConn
	err  error
}

func handshakePair(t *testing.T, server *ServerInstance, client *ClientInstance) (*CommonConn, *CommonConn) {
	t.Helper()
	listener, address := listenLocal(t)
	defer listener.Close()
	serverResult := make(chan handshakeResult, 1)
	go acceptHandshake(listener, server, serverResult)
	rawClient, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = rawClient.SetDeadline(time.Now().Add(5 * time.Second))
	clientConn, err := client.Handshake(rawClient)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	result := <-serverResult
	if result.err != nil {
		t.Fatalf("server handshake: %v", result.err)
	}
	return result.conn, clientConn
}

func acceptHandshake(listener net.Listener, server *ServerInstance, result chan<- handshakeResult) {
	conn, err := listener.Accept()
	if err != nil {
		result <- handshakeResult{err: err}
		return
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	encrypted, err := server.Handshake(conn, nil)
	result <- handshakeResult{conn: encrypted, err: err}
}

func listenLocal(t *testing.T) (net.Listener, string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return listener, listener.Addr().String()
}

func roundTrip(t *testing.T, serverConn, clientConn net.Conn, payload []byte) {
	t.Helper()
	result := make(chan error, 1)
	go func() {
		received := make([]byte, len(payload))
		if _, err := io.ReadFull(serverConn, received); err != nil {
			result <- err
			return
		}
		if string(received) != string(payload) {
			result <- fmt.Errorf("payload mismatch")
			return
		}
		_, err := serverConn.Write(received)
		result <- err
	}()
	written, err := clientConn.Write(payload)
	if err != nil || written != len(payload) {
		t.Fatalf("write = %d, %v", written, err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(clientConn, response); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

type recordConn struct{ bytes.Buffer }

func (*recordConn) Close() error                     { return nil }
func (*recordConn) LocalAddr() net.Addr              { return nil }
func (*recordConn) RemoteAddr() net.Addr             { return nil }
func (*recordConn) SetDeadline(time.Time) error      { return nil }
func (*recordConn) SetReadDeadline(time.Time) error  { return nil }
func (*recordConn) SetWriteDeadline(time.Time) error { return nil }
