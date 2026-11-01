// SPDX-License-Identifier: MPL-2.0
package encryption

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

func TestHandshakeCancellationInterruptsSilentPeer(t *testing.T) {
	cfg, _ := x25519Configs(t, "native", "1rtt")
	server := mustServer(t, cfg)
	defer server.Close()
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := server.HandshakeContext(ctx, left, nil); done <- err }()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled handshake succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("handshake stuck")
	}
}

func TestHandshakeCancellationInterruptsPaddingDelay(t *testing.T) {
	cfg, clientCfg := x25519Configs(t, "native", "1rtt")
	cfg = strings.Replace(cfg, "100-35-35.", "100-35-35.100-10000-10000.", 1)
	server := mustServer(t, cfg)
	defer server.Close()
	left, right := localPair(t)
	defer left.Close()
	defer right.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := server.HandshakeContext(ctx, left, nil); done <- err }()
	client := mustClient(t, clientCfg)
	peer, err := client.Handshake(right)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("padding sleep ignored cancellation")
	}
}

func TestTicketCacheBoundAndClose(t *testing.T) {
	cfg, clientCfg := x25519Configs(t, "native", "0rtt")
	parsed, err := ParseServerConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	server, err := parsed.NewInstanceWithLimit(1)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	for range 3 {
		client := mustClient(t, clientCfg)
		left, right := handshakePair(t, server, client)
		roundTrip(t, left, right, []byte("bounded"))
		left.Close()
		right.Close()
	}
	if len(server.Sessions) != 1 || len(server.Tickets) != 1 {
		t.Fatalf("unbounded tickets: %d/%d", len(server.Sessions), len(server.Tickets))
	}
	server.Close()
	if len(server.Sessions) != 0 || len(server.Tickets) != 0 || len(server.Lasts) != 0 {
		t.Fatal("closed instance retained ticket cache")
	}
}

func TestReplayBudgetRejectsDuplicateAndOverflow(t *testing.T) {
	s := new(ServerSession)
	for i := range maxSessionReplays {
		var key [32]byte
		binary.BigEndian.PutUint32(key[:], uint32(i))
		if err := s.acceptReplayKey(key); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.acceptReplayKey([32]byte{}); err == nil {
		t.Fatal("accepted replay")
	}
	if err := s.acceptReplayKey([32]byte{1}); err == nil {
		t.Fatal("accepted over replay budget")
	}
	if len(s.NfsKeys) != maxSessionReplays {
		t.Fatal("replay cache grew past limit")
	}
}

func TestPaddingIntegerOverflowRejected(t *testing.T) {
	var lens, gaps [][3]int
	if err := ParsePadding("100-9223372036854775807-9223372036854775807.0-0-0.100-9223372036854775807-9223372036854775807", &lens, &gaps); err == nil {
		t.Fatal("accepted overflowing padding")
	}
}

func TestZeroRTTHelloReplayRejected(t *testing.T) {
	cfg, clientCfg := x25519Configs(t, "native", "0rtt")
	server := mustServer(t, cfg)
	defer server.Close()
	client := mustClient(t, clientCfg)
	left, right := handshakePair(t, server, client)
	roundTrip(t, left, right, []byte("ticket"))
	left.Close()
	right.Close()
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	conn, err := client.Handshake(local)
	if err != nil {
		t.Fatal(err)
	}
	hello := append([]byte(nil), conn.PreWrite...)
	for i := range 2 {
		a, b := net.Pipe()
		result := make(chan error, 1)
		go func() { _, err := server.Handshake(a, nil); result <- err }()
		if _, err = b.Write(hello); err != nil {
			t.Fatal(err)
		}
		select {
		case err = <-result:
		case <-time.After(time.Second):
			t.Fatal("replay handshake stuck")
		}
		a.Close()
		b.Close()
		if (err == nil) != (i == 0) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
}

func localPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	listener, address := listenLocal(t)
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() { c, _ := listener.Accept(); accepted <- c }()
	client, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	server := <-accepted
	if server == nil {
		client.Close()
		t.Fatal("accept failed")
	}
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))
	return server, client
}
