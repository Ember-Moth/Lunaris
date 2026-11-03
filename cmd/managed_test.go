// SPDX-License-Identifier: GPL-3.0-only
package cmd

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/store/sqlite"
)

// Seed committed and pending versions separately to exercise restart semantics.
func seedManagedState(t *testing.T, dir string, port int) (string, string) {
	t.Helper()
	ctx := context.Background()
	repo, err := sqlite.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	snapshot := &model.RuntimeConfig{Config: model.NodeConfig{SchemaVersion: 1, Limits: model.DefaultLimits(), Listeners: []model.ListenerSpec{{ID: "ss", Name: "initial", Enabled: true, Protocol: "shadowsocks", Address: "127.0.0.1", Port: uint16(port), Network: []string{"tcp"}, CredentialRefs: []string{"test"}, Options: []byte(`{"method":"aes-128-gcm"}`)}}}, Credentials: map[string][]byte{"test": []byte("process-signal-private-value")}}
	first, err := repo.SaveDraft(ctx, "r0", snapshot)
	if err != nil {
		t.Fatal(err)
	}
	op, _, err := repo.BeginApply(ctx, "seed-committed", first.ID, "r0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repo.CommitApply(ctx, op.ID); err != nil {
		t.Fatal(err)
	}
	snapshot.Config.Listeners[0].Name = "renamed"
	pending, err := repo.SaveDraft(ctx, first.ID, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return first.ID, pending.ID
}

func TestManagedNodeCancellationAndDirectoryOwnership(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.Addr().String()
	port := probe.Addr().(*net.TCPAddr).Port
	probe.Close()
	dir := filepath.Join(t.TempDir(), "state")
	seedManagedState(t, dir, port)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, []string{"managed", "--data-dir", dir}) }()
	var connection net.Conn
	deadline := time.Now().Add(3 * time.Second)
	for {
		connection, err = net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatal("managed node stopped before listening", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("managed node did not listen", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	defer connection.Close()
	if repo, err := sqlite.Open(context.Background(), dir); err == nil {
		repo.Close()
		t.Fatal("running node did not own the data directory")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("managed node failed to stop")
	}
	connection.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := connection.Read(make([]byte, 1)); err == nil {
		t.Fatal("pending handshake survived shutdown")
	}
	repo, err := sqlite.Open(context.Background(), dir)
	if err != nil {
		t.Fatal("shutdown retained data directory", err)
	}
	repo.Close()
}

func TestRemovedNodeYAMLCommands(t *testing.T) {
	for _, args := range [][]string{
		{"run", "--config", "unused.yaml"},
		{"check", "--config", "unused.yaml"},
		{"config", "import", "--config", "unused.yaml"},
		{"managed", "--source", "unused.yaml"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			err := Run(context.Background(), args)
			if err == nil || strings.Contains(err.Error(), "open unused.yaml") {
				t.Fatal("removed node-file entrypoint was accepted or read a file", err)
			}
		})
	}
}
