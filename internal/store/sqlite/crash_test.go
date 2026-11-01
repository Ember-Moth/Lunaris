// SPDX-License-Identifier: GPL-3.0-only
package sqlite

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestAbruptStoreExitHelper(t *testing.T) {
	mode := os.Getenv("LUNARIS_STORE_CRASH_MODE")
	if mode == "" {
		return
	}
	ctx := context.Background()
	store, err := Open(ctx, os.Getenv("LUNARIS_STORE_CRASH_DIR"))
	if err != nil {
		t.Fatal(err)
	}
	old, err := store.SaveDraft(ctx, "r0", storedConfig("old-crash-secret"))
	if err != nil {
		t.Fatal(err)
	}
	first, _, err := store.BeginApply(ctx, "first", old.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitApply(ctx, first.ID); err != nil {
		t.Fatal(err)
	}
	next, err := store.SaveDraft(ctx, old.ID, storedConfig("new-crash-secret"))
	if err != nil {
		t.Fatal(err)
	}
	op, _, err := store.BeginApply(ctx, "crash", next.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetPhase(ctx, op.ID, "committing"); err != nil {
		t.Fatal(err)
	}
	if mode == "after" {
		if _, err := store.CommitApply(ctx, op.ID); err != nil {
			t.Fatal(err)
		}
	}
	// Intentionally bypass Close and all defers, leaving committed WAL pages.
	os.Exit(91)
}

func TestWALBackupAndRecoveryAcrossAbruptExit(t *testing.T) {
	for _, mode := range []string{"before", "after"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			command := exec.Command(os.Args[0], "-test.run=^TestAbruptStoreExitHelper$")
			command.Env = append(os.Environ(), "LUNARIS_STORE_CRASH_MODE="+mode, "LUNARIS_STORE_CRASH_DIR="+dir)
			output, err := command.CombinedOutput()
			if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 91 {
				t.Fatalf("unexpected helper exit: %v %s", err, output)
			}
			info, err := os.Stat(filepath.Join(dir, "lunaris.db-wal"))
			if err != nil || info.Size() == 0 {
				t.Fatal("helper did not leave WAL contents", err)
			}
			backup := filepath.Join(t.TempDir(), "wal-snapshot.db")
			if err := Backup(context.Background(), dir, backup); err != nil {
				t.Fatal(err)
			}
			restoredDir := filepath.Join(t.TempDir(), "restored")
			if err := Restore(context.Background(), restoredDir, backup); err != nil {
				t.Fatal(err)
			}
			store, err := Open(context.Background(), restoredDir)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			op, err := store.Operation(context.Background(), "crash")
			if err != nil {
				t.Fatal(err)
			}
			heads, err := store.Heads(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			expected, secret, status := op.BaseRevision, "old-crash-secret", "interrupted"
			if mode == "after" {
				expected, secret, status = op.TargetRevision, "new-crash-secret", "succeeded"
			}
			if heads.CommittedRevision != expected || op.Status != status {
				t.Fatalf("wrong durable recovery: %+v %+v", heads, op)
			}
			snapshot, err := store.Resolve(context.Background(), expected)
			if err != nil || string(snapshot.Credentials["personal"]) != secret {
				t.Fatal("WAL backup lost committed assets", err)
			}
		})
	}
}
