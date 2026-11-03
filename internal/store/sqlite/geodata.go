// SPDX-License-Identifier: GPL-3.0-only
package sqlite

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/route"
	ports "github.com/Ember-Moth/Lunaris/internal/store"
)

func (s *Store) CreateGeoData(ctx context.Context, kind, label string, data []byte) (model.GeoDataAsset, error) {
	if !validAssetMetadata(kind, label) || route.ValidateGeoData(kind, data) != nil {
		return model.GeoDataAsset{}, ports.ErrInvalidInput
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.GeoDataAsset{}, err
	}
	defer tx.Rollback()
	if err = noRunningOperation(ctx, tx); err != nil {
		return model.GeoDataAsset{}, err
	}
	var id string
	err = tx.QueryRowContext(ctx, "SELECT id FROM geodata_assets WHERE kind=? AND sha256=?", kind, digest).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		id = "geo_" + rand.Text()
		_, err = tx.ExecContext(ctx, "INSERT INTO geodata_assets(id,kind,label,sha256,data) VALUES(?,?,?,?,?)", id, kind, label, digest, data)
	}
	if err != nil {
		return model.GeoDataAsset{}, err
	}
	if err = tx.Commit(); err != nil {
		return model.GeoDataAsset{}, err
	}
	return s.GeoData(ctx, id)
}
func (s *Store) GeoData(ctx context.Context, id string) (model.GeoDataAsset, error) {
	var result model.GeoDataAsset
	err := s.db.QueryRowContext(ctx, "SELECT id,kind,label,sha256,length(data),created_at FROM geodata_assets WHERE id=?", id).Scan(&result.ID, &result.Kind, &result.Label, &result.SHA256, &result.Size, &result.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		err = ports.ErrNotFound
	}
	if err != nil {
		return result, err
	}
	result.References, err = references(ctx, s.db, "revision_geodata", id)
	if err == nil {
		err = s.db.QueryRowContext(ctx, "SELECT count(*) FROM revision_geodata WHERE asset_id=?", id).Scan(&result.ReferenceCount)
	}
	result.ReferencesTruncated = result.ReferenceCount > len(result.References)
	return result, err
}
func (s *Store) GeoDataPage(ctx context.Context, cursor string, limit int) ([]model.GeoDataAsset, string, error) {
	ids, next, err := pageIDs(ctx, s.db, "geodata_assets", cursor, limit)
	if err != nil {
		return nil, "", err
	}
	result := make([]model.GeoDataAsset, 0, len(ids))
	for _, id := range ids {
		asset, err := s.GeoData(ctx, id)
		if err != nil {
			return nil, "", err
		}
		result = append(result, asset)
	}
	return result, next, nil
}
func (s *Store) DeleteGeoData(ctx context.Context, id string) error {
	return s.deleteAsset(ctx, "geodata_assets", "revision_geodata", id)
}
func validateGeoBindings(ctx context.Context, q queryer, refs map[string]string, materials map[string]*model.GeoDataMaterial) error {
	if len(refs) > 2 {
		return ports.ErrInvalidInput
	}
	for kind, id := range refs {
		if (kind != "geosite" && kind != "geoip") || id == "" || len(id) > 128 {
			return ports.ErrInvalidInput
		}
		var actual, digest string
		if err := q.QueryRowContext(ctx, "SELECT kind,sha256 FROM geodata_assets WHERE id=?", id).Scan(&actual, &digest); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ports.ErrNotFound
			}
			return err
		}
		if actual != kind {
			return ports.ErrInvalidInput
		}
		if material := materials[kind]; material != nil && material.Digest() != digest {
			return ports.ErrInvalidInput
		}
	}
	return nil
}
func resolveGeoData(ctx context.Context, q queryer, refs map[string]string) (map[string]*model.GeoDataMaterial, error) {
	if err := validateGeoBindings(ctx, q, refs, nil); err != nil {
		return nil, err
	}
	if len(refs) == 0 {
		return nil, nil
	}
	result := make(map[string]*model.GeoDataMaterial, len(refs))
	for kind, id := range refs {
		var data []byte
		var digest string
		if err := q.QueryRowContext(ctx, "SELECT data,sha256 FROM geodata_assets WHERE id=?", id).Scan(&data, &digest); err != nil {
			return nil, err
		}
		material := model.NewGeoDataMaterial(data)
		if material.Digest() != digest {
			return nil, errors.New("stored geodata digest mismatch")
		}
		result[kind] = material
	}
	return result, nil
}
func saveGeoBindings(ctx context.Context, tx *sql.Tx, revision string, refs map[string]string) error {
	if err := validateGeoBindings(ctx, tx, refs, nil); err != nil {
		return err
	}
	for kind, id := range refs {
		if _, err := tx.ExecContext(ctx, "INSERT INTO revision_geodata(revision_id,logical_id,asset_id) VALUES(?,?,?)", revision, kind, id); err != nil {
			return err
		}
	}
	return nil
}
func checkRevisionGeoBindings(ctx context.Context, q queryer, revision string, refs map[string]string) error {
	rows, err := q.QueryContext(ctx, "SELECT logical_id,asset_id FROM revision_geodata WHERE revision_id=?", revision)
	if err != nil {
		return err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var kind, id string
		if err := rows.Scan(&kind, &id); err != nil {
			return err
		}
		if refs[kind] != id {
			return errors.New("stored geodata references disagree")
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if count != len(refs) {
		return errors.New("stored geodata binding missing")
	}
	return nil
}
