// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors
// Adapted from Polaris 56d52fb44958ef3cc2a7fb841cd240f8206234b2.
package dns

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
)

func TestResolver_rejects_hostile_TCP_question_class(t *testing.T) {
	// Given
	address := startTCPServer(t, func(query []byte) []byte {
		response := makeResponse(query, nil)
		response[len(response)-1] = 2
		return response
	})
	resolver := NewResolver(MustCompile(Config{Servers: []model.DNSServer{{Proto: "tcp", Address: address}}}), Options{Timeout: time.Second})

	// When
	_, err := resolver.Exchange(context.Background(), "example.com", dnsTypeA)

	// Then
	if err == nil {
		t.Fatal("expected hostile TCP response rejection")
	}
}

func TestResolver_rejects_hostile_DoH_question_class(t *testing.T) {
	// Given
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		query, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		response := makeResponse(query, nil)
		response[len(response)-1] = 2
		writer.Header().Set("Content-Type", "application/dns-message")
		if _, writeErr := writer.Write(response); writeErr != nil {
			return
		}
	}))
	defer server.Close()
	resolver := NewResolver(MustCompile(Config{Servers: []model.DNSServer{{Proto: "doh", Address: server.URL}}}), Options{Timeout: time.Second})
	resolver.client = server.Client()

	// When
	_, err := resolver.Exchange(context.Background(), "example.com", dnsTypeA)

	// Then
	if err == nil {
		t.Fatal("expected hostile DoH response rejection")
	}
}

func TestResolver_rejects_untrusted_DoT_peer(t *testing.T) {
	// Given
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	resolver := NewResolver(MustCompile(Config{Servers: []model.DNSServer{{
		Proto:      "dot",
		Address:    server.Listener.Addr().String(),
		ServerName: "dns.example",
	}}}), Options{Timeout: time.Second})

	// When
	_, err := resolver.Exchange(context.Background(), "example.com", dnsTypeA)

	// Then
	if err == nil {
		t.Fatal("expected untrusted DoT peer rejection")
	}
}

func startTCPServer(t *testing.T, respond func([]byte) []byte) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen TCP: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = connection.Close() }()
		var size [2]byte
		if _, readErr := io.ReadFull(connection, size[:]); readErr != nil {
			return
		}
		query := make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, readErr := io.ReadFull(connection, query); readErr != nil {
			return
		}
		response := respond(query)
		var frame [2]byte
		binary.BigEndian.PutUint16(frame[:], uint16(len(response)))
		if _, writeErr := connection.Write(frame[:]); writeErr != nil {
			return
		}
		if _, writeErr := connection.Write(response); writeErr != nil {
			return
		}
	}()
	return listener.Addr().String()
}
