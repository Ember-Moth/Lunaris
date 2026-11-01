//go:build webui

// SPDX-License-Identifier: GPL-3.0-only
package cmd

import (
	"context"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestServeClosesIdleConnectionsOnCancellation(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.Addr().String()
	probe.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, []string{"serve", "--listen", address, "--data-dir", filepath.Join(t.TempDir(), "state")})
	}()
	transport := &http.Transport{}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	deadline := time.Now().Add(5 * time.Second)
	for {
		response, err := client.Get("http://" + address + "/healthz")
		if err == nil {
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode != 200 {
				t.Fatalf("unexpected status %d", response.StatusCode)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("service failed to start", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Keep a second, incomplete HTTP request open while canceling the process.
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := io.WriteString(connection, "GET / HTTP/1.1\r\nHost: localhost\r\n"); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("normal shutdown returned an error: %v", err)
		}
	case <-time.After(7 * time.Second):
		t.Fatal("shutdown did not finish")
	}
	connection.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 1024)
	for {
		_, err = connection.Read(buffer)
		if err != nil {
			break
		}
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("HTTP connection survived shutdown")
	}
}
