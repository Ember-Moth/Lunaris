// SPDX-License-Identifier: GPL-3.0-only
package cmd

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/Ember-Moth/Lunaris/internal/model"
	ports "github.com/Ember-Moth/Lunaris/internal/store"
	"github.com/Ember-Moth/Lunaris/internal/store/sqlite"
)

func TestOfflineConfigurationCommandsAndBackup(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dir := filepath.Join(root, "state")
	store, err := sqlite.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := store.SaveDraft(ctx, "r0", &model.RuntimeConfig{Config: model.NodeConfig{SchemaVersion: 1, Limits: model.DefaultLimits(), Listeners: []model.ListenerSpec{}}, Credentials: map[string][]byte{"personal": []byte("cli-test-private-value")}})
	if err != nil {
		t.Fatal(err)
	}
	if saved.ID == "r0" {
		t.Fatal("fixture did not create a draft")
	}
	heads, err := store.Heads(ctx)
	if err != nil {
		t.Fatal(err)
	}
	store.Close()
	if heads.CommittedRevision != "r0" || heads.DraftRevision == "r0" {
		t.Fatalf("saving a draft activated config: %+v", heads)
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
