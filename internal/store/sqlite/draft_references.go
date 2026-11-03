// SPDX-License-Identifier: GPL-3.0-only
package sqlite

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/Ember-Moth/Lunaris/internal/model"
	ports "github.com/Ember-Moth/Lunaris/internal/store"
)

func resolveDraftInput(ctx context.Context, q queryer, input model.DraftInput, loadGeo bool) (*model.RuntimeConfig, error) {
	snapshot := &model.RuntimeConfig{Config: input.Config, Credentials: make(map[string][]byte), Certificates: make(map[string]model.Certificate)}
	if len(input.CredentialAssets) > 4096 || len(input.CertificateAssets) > 1024 {
		return nil, ports.ErrInvalidInput
	}
	for name, id := range input.CredentialAssets {
		if len(name) == 0 || len(name) > 128 || len(id) > 128 {
			return nil, ports.ErrInvalidInput
		}
		var value []byte
		err := q.QueryRowContext(ctx, "SELECT secret FROM credential_assets WHERE id=?", id).Scan(&value)
		if errors.Is(err, sql.ErrNoRows) {
			err = ports.ErrNotFound
		}
		if err != nil {
			return nil, err
		}
		snapshot.Credentials[name] = bytes.Clone(value)
	}
	for name, id := range input.CertificateAssets {
		if len(name) == 0 || len(name) > 128 || len(id) > 128 {
			return nil, ports.ErrInvalidInput
		}
		var value model.Certificate
		err := q.QueryRowContext(ctx, "SELECT certificate,private_key FROM certificate_assets WHERE id=?", id).Scan(&value.Certificate, &value.PrivateKey)
		if errors.Is(err, sql.ErrNoRows) {
			err = ports.ErrNotFound
		}
		if err != nil {
			return nil, err
		}
		snapshot.Certificates[name] = value
	}
	if loadGeo {
		var err error
		snapshot.GeoData, err = resolveGeoData(ctx, q, input.Config.GeoData)
		if err != nil {
			return nil, err
		}
	} else {
		if err := validateGeoBindings(ctx, q, input.Config.GeoData, nil); err != nil {
			return nil, err
		}
	}
	return snapshot, nil
}
func (s *Store) ResolveDraftInput(ctx context.Context, input model.DraftInput) (*model.RuntimeConfig, error) {
	return resolveDraftInput(ctx, s.db, input, true)
}
func (s *Store) SaveDraftReferences(ctx context.Context, expected string, input model.DraftInput) (model.ConfigRevision, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.ConfigRevision{}, err
	}
	defer tx.Rollback()
	if err = noRunningOperation(ctx, tx); err != nil {
		return model.ConfigRevision{}, err
	}
	current, err := heads(ctx, tx)
	if err != nil {
		return model.ConfigRevision{}, err
	}
	if expected == "" || current.DraftRevision != expected {
		return model.ConfigRevision{}, ports.ErrConflict
	}
	if _, err = resolveDraftInput(ctx, tx, input, false); err != nil {
		return model.ConfigRevision{}, err
	}
	old, err := revision(ctx, tx, expected)
	if err != nil {
		return model.ConfigRevision{}, err
	}
	document, err := json.Marshal(input.Config)
	if err != nil {
		return model.ConfigRevision{}, err
	}
	previous, _ := json.Marshal(old.Config)
	if bytes.Equal(document, previous) && reflect.DeepEqual(old.CredentialAssets, normalizedBindings(input.CredentialAssets)) && reflect.DeepEqual(old.CertificateAssets, normalizedBindings(input.CertificateAssets)) {
		return old, nil
	}
	id := "r_" + rand.Text()
	if _, err = tx.ExecContext(ctx, "INSERT INTO config_revisions(id,parent_id,schema_version,document) VALUES(?,?,?,?)", id, expected, input.Config.SchemaVersion, string(document)); err != nil {
		return model.ConfigRevision{}, err
	}
	for name, asset := range input.CredentialAssets {
		if _, err = tx.ExecContext(ctx, "INSERT INTO revision_credentials(revision_id,logical_id,asset_id) VALUES(?,?,?)", id, name, asset); err != nil {
			return model.ConfigRevision{}, err
		}
	}
	for name, asset := range input.CertificateAssets {
		if _, err = tx.ExecContext(ctx, "INSERT INTO revision_certificates(revision_id,logical_id,asset_id) VALUES(?,?,?)", id, name, asset); err != nil {
			return model.ConfigRevision{}, err
		}
	}
	if err = saveGeoBindings(ctx, tx, id, input.Config.GeoData); err != nil {
		return model.ConfigRevision{}, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE config_heads SET draft_revision=? WHERE id=1", id); err != nil {
		return model.ConfigRevision{}, err
	}
	saved, err := revision(ctx, tx, id)
	if err != nil {
		return saved, err
	}
	return saved, tx.Commit()
}
func normalizedBindings(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}
