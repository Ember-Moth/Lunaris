// SPDX-License-Identifier: GPL-3.0-only
package cmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	ports "github.com/Ember-Moth/Lunaris/internal/store"
	"github.com/Ember-Moth/Lunaris/internal/store/sqlite"
)

func TestOfflineConfigurationCommandsAndBackup(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dir := filepath.Join(root, "state")
	path := filepath.Join(root, "node.yaml")
	if err := os.WriteFile(path, []byte("schema_version: 1\ncredentials:\n  - id: personal\n    secret: cli-test-private-value\nlisteners: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Run(ctx, []string{"config", "import", "--data-dir", dir, "--config", path, "--expect", "r0"}); err != nil {
		t.Fatal(err)
	}
	store, err := sqlite.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	heads, err := store.Heads(ctx)
	if err != nil {
		t.Fatal(err)
	}
	store.Close()
	if heads.CommittedRevision != "r0" || heads.DraftRevision == "r0" {
		t.Fatalf("import activated config: %+v", heads)
	}
	if err := Run(ctx, []string{"config", "apply", "--data-dir", dir, "--revision", heads.DraftRevision, "--request-id", "cli-apply"}); err != nil {
		t.Fatal(err)
	}
	if err := Run(ctx, []string{"config", "apply", "--data-dir", dir, "--revision", heads.DraftRevision, "--request-id", "cli-apply"}); err != nil {
		t.Fatal(err)
	}
	if err := Run(ctx, []string{"config", "apply", "--data-dir", dir, "--revision", "r0", "--request-id", "cli-apply"}); !errors.Is(err, ports.ErrIdempotencyConflict) {
		t.Fatalf("CLI accepted conflicting request key: %v", err)
	}
	backup := filepath.Join(root, "backup.db")
	if err := Run(ctx, []string{"backup", "--data-dir", dir, "--output", backup}); err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(root, "restored")
	if err := Run(ctx, []string{"restore", "--data-dir", restored, "--input", backup}); err != nil {
		t.Fatal(err)
	}
	store, err = sqlite.Open(ctx, restored)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	loaded, err := store.Heads(ctx)
	if err != nil || loaded.CommittedRevision != heads.DraftRevision {
		t.Fatal("CLI backup lost commit", err)
	}
}
