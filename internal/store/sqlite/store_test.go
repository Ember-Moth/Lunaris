// SPDX-License-Identifier: GPL-3.0-only
package sqlite

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestInitializeLockAndReopen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if duplicate, err := Open(ctx, dir); err == nil {
		duplicate.Close()
		t.Fatal("second process owner was accepted")
	}
	first, err := store.Heads(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if first.DraftRevision != "r0" || first.CommittedRevision != "r0" {
		t.Fatalf("unexpected initial heads: %+v", first)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	second, err := reopened.Heads(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("configuration changed after restart: %+v -> %+v", first, second)
	}
	var count int
	if err := reopened.db.QueryRowContext(ctx, "SELECT count(*) FROM schema_migrations").Scan(&count); err != nil {
		t.Fatal(err)
	}
	expected, _ := manifest()
	if count != len(expected) {
		t.Fatalf("migration applied more than once: %d", count)
	}
}

func TestRejectUnknownSchemaAndReleaseLock(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, "INSERT INTO schema_migrations(name, checksum) VALUES ('9999_future.sql', 'future')"); err != nil {
		t.Fatal(err)
	}
	store.Close()
	if rejected, err := Open(ctx, dir); err == nil {
		rejected.Close()
		t.Fatal("unknown schema accepted")
	}
	lock, err := acquireLock(filepath.Join(dir, "lunaris.lock"))
	if err != nil {
		t.Fatalf("failed open leaked data directory lock: %v", err)
	}
	lock.Close()
}

func TestCorruptDatabaseIsNotReplaced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lunaris.db")
	original := []byte("this is not a database")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if store, err := Open(context.Background(), dir); err == nil {
		store.Close()
		t.Fatal("corrupt database accepted")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatal("corrupt database was replaced")
	}
}
