//go:build linux || darwin

// SPDX-License-Identifier: GPL-3.0-only
package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/config"
)

type signalLog struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (l *signalLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buffer.Write(p)
}
func (l *signalLog) text() string { l.mu.Lock(); defer l.mu.Unlock(); return l.buffer.String() }

func TestNodeSignalHelper(t *testing.T) {
	if os.Getenv("LUNARIS_NODE_SIGNAL_HELPER") != "1" {
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := Run(ctx, []string{"managed", "--data-dir", os.Getenv("LUNARIS_NODE_SIGNAL_DATA_DIR")}); err != nil {
		t.Fatal(err)
	}
}

func TestProcessSignalsReloadAndReportStatus(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	probe.Close()
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	committed, draft := seedManagedState(t, stateDir, port)
	var output signalLog
	command := exec.Command(os.Args[0], "-test.run=^TestNodeSignalHelper$", "-test.timeout=30s")
	command.Env = append(os.Environ(), "LUNARIS_NODE_SIGNAL_HELPER=1", "LUNARIS_NODE_SIGNAL_DATA_DIR="+stateDir)
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	finished := false
	t.Cleanup(func() {
		if !finished {
			command.Process.Kill()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("signal helper did not exit")
			}
		}
	})
	wait := func(needle string, previous int) string {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			text := output.text()
			if strings.Count(text, needle) > previous {
				return text
			}
			select {
			case err := <-done:
				finished = true
				t.Fatalf("node exited early: %v\n%s", err, text)
			default:
			}
			if time.Now().After(deadline) {
				t.Fatalf("missing %q\n%s", needle, text)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	wait("Managed node started", 0)
	status := func() config.ServiceStatus {
		t.Helper()
		previous := strings.Count(output.text(), "Managed node status")
		if err := command.Process.Signal(syscall.SIGUSR1); err != nil {
			t.Fatal(err)
		}
		text := wait("Managed node status", previous)
		var line string
		for _, candidate := range strings.Split(text, "\n") {
			if strings.Contains(candidate, "Managed node status") {
				line = candidate
			}
		}
		_, raw, found := strings.Cut(line, " status=")
		if !found {
			t.Fatal("status field missing")
		}
		decoded, err := strconv.Unquote(raw)
		if err != nil {
			t.Fatal(err)
		}
		var result config.ServiceStatus
		if err := json.Unmarshal([]byte(decoded), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	initial := status()
	if initial.Heads.CommittedRevision != committed || initial.Heads.DraftRevision != draft || initial.RuntimeRevision != committed || initial.Runtime.Listeners[0].Name != "initial" {
		t.Fatalf("startup applied an uncommitted draft: %+v", initial)
	}
	if err := command.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	wait("Managed configuration committed", 0)
	updated := status()
	if updated.Heads.CommittedRevision != draft || updated.RuntimeRevision != draft || updated.Runtime.Revision != initial.Runtime.Revision+1 || updated.Runtime.Listeners[0].Generation != initial.Runtime.Listeners[0].Generation || updated.Runtime.Listeners[0].Name != "renamed" {
		t.Fatalf("incorrect signal update: %+v", updated)
	}
	if err := command.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	wait("Managed configuration committed", 1)
	repeated := status()
	if repeated.Runtime.Revision != updated.Runtime.Revision || repeated.Runtime.Listeners[0].Generation != updated.Runtime.Listeners[0].Generation {
		t.Fatal("reapplying committed configuration replaced an unchanged listener")
	}
	if strings.Contains(output.text(), "process-signal-private-value") {
		t.Fatal("signals exposed a credential")
	}
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		finished = true
		if err != nil {
			t.Fatal(err, output.text())
		}
	case <-time.After(7 * time.Second):
		t.Fatal("signal helper shutdown timed out")
	}
}
