// SPDX-License-Identifier: GPL-3.0-only
package cmd

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunNodeYAMLAndCancellation(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.Addr().String()
	port := probe.Addr().(*net.TCPAddr).Port
	probe.Close()
	t.Setenv("LUNARIS_TEST_RUN_PASSWORD", "run-command-test-password")
	path := filepath.Join(t.TempDir(), "node.yaml")
	content := fmt.Sprintf("schema_version: 1\ncredentials:\n  - id: test\n    secret_env: LUNARIS_TEST_RUN_PASSWORD\nlisteners:\n  - id: ss\n    protocol: shadowsocks\n    address: 127.0.0.1\n    port: %d\n    network: [tcp]\n    credential_refs: [test]\n    options:\n      method: aes-128-gcm\n", port)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), []string{"check", "--config", path}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, []string{"run", "--config", path}) }()
	var connection net.Conn
	deadline := time.Now().Add(3 * time.Second)
	for {
		connection, err = net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatal("node stopped before listening", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("node did not listen", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	defer connection.Close()
	// Checking config must not attempt to bind the already-owned port.
	if err := Run(context.Background(), []string{"check", "--config", path}); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("node failed to stop")
	}
	connection.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := connection.Read(make([]byte, 1)); err == nil {
		t.Fatal("pending handshake survived shutdown")
	}
}
