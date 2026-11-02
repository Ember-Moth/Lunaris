// SPDX-License-Identifier: GPL-3.0-only
package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/auth"
	"github.com/Ember-Moth/Lunaris/internal/model"
	ports "github.com/Ember-Moth/Lunaris/internal/store"
)

func TestRestoreRevokesSessionsAndSetupTokens(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	token := auth.Token()
	if err = s.SetSetupToken(ctx, auth.TokenHash(token), time.Now().Add(time.Hour), false); err != nil {
		t.Fatal(err)
	}
	hash, err := auth.HashPassword("backup-administrator-password")
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.InitializeAdmin(ctx, auth.TokenHash(token), "admin", hash, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	sessionToken := auth.Token()
	session := model.AdminSession{TokenHash: auth.TokenHash(sessionToken), AccountID: a.ID, AccountVersion: a.Version, CSRFToken: auth.Token(), CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
	if err = s.CreateAdminSession(ctx, session); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(t.TempDir(), "backup.db")
	if err = Backup(ctx, dir, backup); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	if err = Restore(ctx, target, backup); err != nil {
		t.Fatal(err)
	}
	restored, err := Open(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	account, err := restored.AdminAccount(ctx)
	if err != nil || !auth.VerifyPassword(account.PasswordHash, "backup-administrator-password") {
		t.Fatal("administrator was not restored", err)
	}
	if _, _, err := restored.AdminSession(ctx, session.TokenHash, time.Now()); !errors.Is(err, ports.ErrNotFound) {
		t.Fatal("backup resurrected session", err)
	}
	state, err := restored.AuthSetupState(ctx)
	if err != nil || !state.Initialized || state.TokenHash != "" {
		t.Fatal(state, err)
	}
	// The source backup and original installation remain unchanged.
	original, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	if _, _, err := original.AdminSession(ctx, session.TokenHash, time.Now()); err != nil {
		t.Fatal("restore altered source session", err)
	}
}
func TestSessionLimitAndCredentialMetadata(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	token := auth.Token()
	_ = s.SetSetupToken(ctx, auth.TokenHash(token), time.Now().Add(time.Hour), false)
	a, err := s.InitializeAdmin(ctx, auth.TokenHash(token), "admin", "stored-test-hash", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for i := range 40 {
		v := model.AdminSession{TokenHash: auth.TokenHash(auth.Token()), AccountID: a.ID, AccountVersion: a.Version, CSRFToken: auth.Token(), CreatedAt: time.Now().Add(time.Duration(i) * time.Second), ExpiresAt: time.Now().Add(time.Hour)}
		if err = s.CreateAdminSession(ctx, v); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err = s.db.QueryRowContext(ctx, "SELECT count(*) FROM admin_sessions").Scan(&count); err != nil || count != 32 {
		t.Fatal(count, err)
	}
	asset, err := s.CreateCredential(ctx, "password", "label", []byte("private-value"))
	if err != nil {
		t.Fatal(err)
	}
	if asset.Kind != "password" || asset.Label != "label" || asset.ReferenceCount != 0 {
		t.Fatal(asset)
	}
	if err = s.DeleteCredential(ctx, asset.ID); err != nil {
		t.Fatal(err)
	}
}
