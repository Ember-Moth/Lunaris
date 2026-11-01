// SPDX-License-Identifier: GPL-3.0-only
package sqlite

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/testutil"
	"path/filepath"
	"testing"
)

func TestCertificateRevisionBackupAndRestore(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	first, _ := testutil.Certificate(t)
	next, _ := testutil.Certificate(t)
	input := storedConfig("password")
	input.Certificates = map[string]model.Certificate{"tls": first}
	a, err := s.SaveDraft(ctx, "r0", input)
	if err != nil {
		t.Fatal(err)
	}
	same, err := s.SaveDraft(ctx, a.ID, input)
	if err != nil || same.ID != a.ID {
		t.Fatal("unchanged certificates created revision", err)
	}
	// Keep the old certificate committed and a newer certificate only in draft.
	op, _, err := s.BeginApply(ctx, "commit-first", a.ID, "r0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.CommitApply(ctx, op.ID); err != nil {
		t.Fatal(err)
	}
	input.Certificates["tls"] = next
	b, err := s.SaveDraft(ctx, a.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	if a.CertificateAssets["tls"] == b.CertificateAssets["tls"] {
		t.Fatal("certificate changed without new asset")
	}
	if _, err = s.db.ExecContext(ctx, "UPDATE certificate_assets SET private_key=? WHERE id=?", first.PrivateKey, b.CertificateAssets["tls"]); err == nil {
		t.Fatal("certificate mutation accepted")
	}
	encoded, _ := json.Marshal(b)
	if bytes.Contains(encoded, next.PrivateKey) || bytes.Contains(encoded, next.Certificate) {
		t.Fatal("certificate bytes exposed in metadata")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(t.TempDir(), "certificates.db")
	if err = Backup(ctx, dir, backup); err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(t.TempDir(), "restored")
	if err = Restore(ctx, restored, backup); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(ctx, restored)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	heads, err := s2.Heads(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if heads.CommittedRevision != a.ID || heads.DraftRevision != b.ID {
		t.Fatal("backup lost revision heads")
	}
	for id, want := range map[string]model.Certificate{a.ID: first, b.ID: next} {
		got, err := s2.Resolve(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		asset := got.Certificates["tls"]
		if !bytes.Equal(asset.Certificate, want.Certificate) || !bytes.Equal(asset.PrivateKey, want.PrivateKey) {
			t.Fatal("certificate revision not restored")
		}
	}
}
