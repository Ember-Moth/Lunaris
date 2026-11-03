// SPDX-License-Identifier: GPL-3.0-only
package sqlite

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"testing"

	"github.com/Ember-Moth/Lunaris/internal/model"
	ports "github.com/Ember-Moth/Lunaris/internal/store"
	"google.golang.org/protobuf/encoding/protowire"
)

func siteData(domain string) []byte {
	item := protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), 3)
	item = protowire.AppendString(protowire.AppendTag(item, 2, protowire.BytesType), domain)
	category := protowire.AppendString(protowire.AppendTag(nil, 1, protowire.BytesType), "TEST")
	category = protowire.AppendBytes(protowire.AppendTag(category, 2, protowire.BytesType), item)
	return protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), category)
}
func TestGeoDataRevisionOwnershipBackupAndDeletion(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "state")
	repo, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	data := siteData("blocked.test")
	asset, err := repo.CreateGeoData(ctx, "geosite", "test", data)
	if err != nil {
		t.Fatal(err)
	}
	same, err := repo.CreateGeoData(ctx, "geosite", "retry", data)
	if err != nil || same.ID != asset.ID {
		t.Fatal("content retry did not converge", same, err)
	}
	input := model.DraftInput{Config: model.NodeConfig{SchemaVersion: 1, Limits: model.DefaultLimits(), Listeners: []model.ListenerSpec{}, Route: &model.RouteConfig{Block: []string{"geosite:test"}}, GeoData: map[string]string{"geosite": asset.ID}}}
	saved, err := repo.SaveDraftReferences(ctx, "r0", input)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := repo.Resolve(ctx, saved.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.GeoData["geosite"].Digest() != asset.SHA256 {
		t.Fatal("wrong geodata material")
	}
	content, _ := io.ReadAll(loaded.GeoData["geosite"].Open())
	content[0] ^= 255
	unchanged, _ := io.ReadAll(loaded.GeoData["geosite"].Open())
	if string(unchanged) != string(data) {
		t.Fatal("material reader exposed mutable storage")
	}
	if err := repo.DeleteGeoData(ctx, asset.ID); !errors.Is(err, ports.ErrReferenced) {
		t.Fatal("referenced dataset deleted", err)
	}
	copied, err := repo.SaveDraft(ctx, saved.ID, loaded)
	if err != nil || copied.ID != saved.ID {
		t.Fatal("same version changed", copied, err)
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(t.TempDir(), "copy.db")
	if err := Backup(ctx, dir, backup); err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(t.TempDir(), "restored")
	if err := Restore(ctx, restored, backup); err != nil {
		t.Fatal(err)
	}
	repo, err = Open(ctx, restored)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	loaded, err = repo.Resolve(ctx, saved.ID)
	if err != nil || loaded.GeoData["geosite"].Digest() != asset.SHA256 {
		t.Fatal("restored dataset missing", err)
	}
	fresh, err := repo.CreateGeoData(ctx, "geosite", "new", siteData("other.test"))
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.DeleteGeoData(ctx, fresh.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateGeoData(ctx, "geoip", "wrong kind", data); err == nil {
		t.Fatal("dataset kind mismatch accepted")
	}
	if _, err := repo.db.ExecContext(ctx, "UPDATE geodata_assets SET label='changed' WHERE id=?", asset.ID); err == nil {
		t.Fatal("immutable asset changed")
	}
}
