// SPDX-License-Identifier: GPL-3.0-only
package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Ember-Moth/Lunaris/internal/model"
	ports "github.com/Ember-Moth/Lunaris/internal/store"
)

func storedConfig(secret string) *model.RuntimeConfig {
	return &model.RuntimeConfig{Config: model.NodeConfig{SchemaVersion: 1, Limits: model.DefaultLimits(), Listeners: []model.ListenerSpec{}}, Credentials: map[string][]byte{"personal": []byte(secret)}}
}

func TestImmutableAssetsCASAndIdempotency(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	initial := storedConfig("")
	initial.Credentials = map[string][]byte{}
	empty, err := store.SaveDraft(ctx, "r0", initial)
	if err != nil || empty.ID != "r0" {
		t.Fatal("legacy empty revision was duplicated", err)
	}
	first, err := store.SaveDraft(ctx, "r0", storedConfig("old-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveDraft(ctx, "r0", storedConfig("lost-update")); !errors.Is(err, ports.ErrConflict) {
		t.Fatalf("stale draft accepted: %v", err)
	}
	unchanged, err := store.SaveDraft(ctx, first.ID, storedConfig("old-secret"))
	if err != nil || unchanged.ID != first.ID {
		t.Fatalf("unchanged draft duplicated: %+v %v", unchanged, err)
	}
	second, err := store.SaveDraft(ctx, first.ID, storedConfig("new-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if first.CredentialAssets["personal"] == second.CredentialAssets["personal"] {
		t.Fatal("credential rotation mutated an asset")
	}
	old, err := store.Resolve(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if string(old.Credentials["personal"]) != "old-secret" {
		t.Fatal("historical credential changed")
	}
	encoded, _ := json.Marshal(second)
	if bytes.Contains(encoded, []byte("new-secret")) {
		t.Fatal("revision metadata exposed secret")
	}
	if _, err := store.db.ExecContext(ctx, "UPDATE credential_assets SET secret=? WHERE id=?", []byte("changed"), first.CredentialAssets["personal"]); err == nil {
		t.Fatal("immutable credential updated")
	}
	op, replay, err := store.BeginApply(ctx, "request-1", second.ID, "r0")
	if err != nil || replay {
		t.Fatal(err)
	}
	if _, err := store.SaveDraft(ctx, second.ID, storedConfig("blocked")); !errors.Is(err, ports.ErrBusy) {
		t.Fatalf("draft changed during apply: %v", err)
	}
	duplicate, replay, err := store.BeginApply(ctx, "request-1", second.ID, "r0")
	if err != nil || !replay || duplicate.ID != op.ID {
		t.Fatal("running retry not idempotent")
	}
	if _, _, err := store.BeginApply(ctx, "request-1", first.ID, "r0"); !errors.Is(err, ports.ErrIdempotencyConflict) {
		t.Fatal("request key reused for other target")
	}
	committed, err := store.CommitApply(ctx, op.ID)
	if err != nil || committed.Status != "succeeded" {
		t.Fatal(err)
	}
	heads, _ := store.Heads(ctx)
	if heads.CommittedRevision != second.ID {
		t.Fatal("commit pointer not advanced")
	}
	duplicate, replay, err = store.BeginApply(ctx, "request-1", second.ID, "r0")
	if err != nil || !replay || duplicate.Status != "succeeded" {
		t.Fatal("completed retry changed result")
	}
	if _, err := store.FinishApply(ctx, op.ID, "failed", "overwrite"); !errors.Is(err, ports.ErrConflict) {
		t.Fatal("terminal operation overwritten")
	}
}

func TestInterruptedApplyDoesNotBecomeCommitted(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	draft, err := store.SaveDraft(ctx, "r0", storedConfig("pending-secret"))
	if err != nil {
		t.Fatal(err)
	}
	op, _, err := store.BeginApply(ctx, "interrupted-key", draft.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetPhase(ctx, op.ID, "committing"); err != nil {
		t.Fatal(err)
	}
	store.Close()
	reopened, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	heads, _ := reopened.Heads(ctx)
	if heads.CommittedRevision != "r0" || heads.DraftRevision != draft.ID {
		t.Fatalf("interrupted draft activated: %+v", heads)
	}
	interrupted, err := reopened.Operation(ctx, "interrupted-key")
	if err != nil || interrupted.Status != "interrupted" {
		t.Fatalf("operation not recovered: %+v %v", interrupted, err)
	}
	retained, replay, err := reopened.BeginApply(ctx, "interrupted-key", draft.ID, "")
	if err != nil || !replay || retained.Status != "interrupted" {
		t.Fatal("interrupted key was executed again")
	}
}

func TestBackupRestoreAndNoClobber(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := store.SaveDraft(ctx, "r0", storedConfig("backup-secret"))
	if err != nil {
		t.Fatal(err)
	}
	op, _, err := store.BeginApply(ctx, "backup-apply", revision.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitApply(ctx, op.ID); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(t.TempDir(), "snapshot.db")
	if err := Backup(ctx, dir, backup); err == nil {
		t.Fatal("backup did not honor live node lock")
	}
	store.Close()
	if err := Backup(ctx, dir, backup); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(backup)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("backup is not private", err)
	}
	if err := Backup(ctx, dir, backup); !errors.Is(err, os.ErrExist) {
		t.Fatalf("backup overwrote existing output: %v", err)
	}
	restoredDir := filepath.Join(t.TempDir(), "restored")
	if err := Restore(ctx, restoredDir, backup); err != nil {
		t.Fatal(err)
	}
	if err := Restore(ctx, restoredDir, backup); err == nil {
		t.Fatal("restore overwrote existing node data")
	}
	restored, err := Open(ctx, restoredDir)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	heads, _ := restored.Heads(ctx)
	if heads.CommittedRevision != revision.ID {
		t.Fatal("backup lost committed head")
	}
	snapshot, err := restored.Resolve(ctx, revision.ID)
	if err != nil || string(snapshot.Credentials["personal"]) != "backup-secret" {
		t.Fatal("backup lost credential", err)
	}
	operation, err := restored.Operation(ctx, "backup-apply")
	if err != nil || operation.Status != "succeeded" {
		t.Fatal("backup lost idempotency history", err)
	}
}

func TestMigrationTakesBackupBeforeChangingSchema(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "lunaris.db")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	known, err := manifest()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "CREATE TABLE schema_migrations(name TEXT PRIMARY KEY, checksum TEXT NOT NULL, applied_at TEXT NOT NULL DEFAULT '')"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, string(known[0].content)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO schema_migrations(name,checksum) VALUES(?,?)", known[0].name, known[0].checksum); err != nil {
		t.Fatal(err)
	}
	db.Close()
	store, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	entries, err := os.ReadDir(filepath.Join(dir, "migration-backups"))
	if err != nil || len(entries) != 1 {
		t.Fatal("pre-migration backup missing", err)
	}
	backup, err := openReadOnly(ctx, filepath.Join(dir, "migration-backups", entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	defer backup.Close()
	count, err := migrationCount(ctx, backup, known)
	if err != nil || count != 1 {
		t.Fatalf("backup was taken after migration: %d %v", count, err)
	}
}
