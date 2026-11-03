// SPDX-License-Identifier: GPL-3.0-only
package sqlite

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/Ember-Moth/Lunaris/internal/model"
	ports "github.com/Ember-Moth/Lunaris/internal/store"
)

type queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func heads(ctx context.Context, q queryer) (model.ConfigHeads, error) {
	var result model.ConfigHeads
	err := q.QueryRowContext(ctx, "SELECT draft_revision, committed_revision FROM config_heads WHERE id=1").Scan(&result.DraftRevision, &result.CommittedRevision)
	return result, err
}

func noRunningOperation(ctx context.Context, q queryer) error {
	var count int
	if err := q.QueryRowContext(ctx, "SELECT count(*) FROM apply_operations WHERE status='running'").Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return ports.ErrBusy
	}
	return nil
}

func bindings(ctx context.Context, q queryer, revision string) (map[string]string, map[string][]byte, error) {
	rows, err := q.QueryContext(ctx, `SELECT b.logical_id,b.asset_id,a.secret FROM revision_credentials b
		JOIN credential_assets a ON a.id=b.asset_id WHERE b.revision_id=? ORDER BY b.logical_id`, revision)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	ids := make(map[string]string)
	secrets := make(map[string][]byte)
	for rows.Next() {
		var name, id string
		var secret []byte
		if err := rows.Scan(&name, &id, &secret); err != nil {
			return nil, nil, err
		}
		ids[name] = id
		secrets[name] = bytes.Clone(secret)
	}
	return ids, secrets, rows.Err()
}

func bindingIDs(ctx context.Context, q queryer, revision string) (map[string]string, error) {
	rows, err := q.QueryContext(ctx, "SELECT logical_id,asset_id FROM revision_credentials WHERE revision_id=? ORDER BY logical_id", revision)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]string)
	for rows.Next() {
		var name, id string
		if err := rows.Scan(&name, &id); err != nil {
			return nil, err
		}
		result[name] = id
	}
	return result, rows.Err()
}

func (s *Store) SaveDraft(ctx context.Context, expected string, snapshot *model.RuntimeConfig) (model.ConfigRevision, error) {
	if expected == "" {
		return model.ConfigRevision{}, ports.ErrConflict
	}
	if snapshot == nil {
		return model.ConfigRevision{}, errors.New("configuration snapshot required")
	}
	for name, secret := range snapshot.Credentials {
		if name == "" || len(secret) == 0 || len(secret) > 4096 {
			return model.ConfigRevision{}, errors.New("invalid credential asset")
		}
	}
	for id, cert := range snapshot.Certificates {
		if id == "" || len(cert.Certificate) > 1<<20 || len(cert.PrivateKey) > 1<<20 {
			return model.ConfigRevision{}, errors.New("invalid certificate asset")
		}
		if _, err := tls.X509KeyPair(cert.Certificate, cert.PrivateKey); err != nil {
			return model.ConfigRevision{}, errors.New("invalid certificate key pair")
		}
	}
	document, err := json.Marshal(snapshot.Config)
	if err != nil {
		return model.ConfigRevision{}, errors.New("cannot encode configuration")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.ConfigRevision{}, err
	}
	defer tx.Rollback()
	if err := noRunningOperation(ctx, tx); err != nil {
		return model.ConfigRevision{}, err
	}
	current, err := heads(ctx, tx)
	if err != nil {
		return model.ConfigRevision{}, err
	}
	if current.DraftRevision != expected {
		return model.ConfigRevision{}, ports.ErrConflict
	}
	if err := validateGeoBindings(ctx, tx, snapshot.Config.GeoData, snapshot.GeoData); err != nil {
		return model.ConfigRevision{}, err
	}
	oldAssets, oldSecrets, err := bindings(ctx, tx, expected)
	if err != nil {
		return model.ConfigRevision{}, err
	}
	oldCertIDs, oldCerts, err := certificateBindings(ctx, tx, expected)
	if err != nil {
		return model.ConfigRevision{}, err
	}
	previous, err := revision(ctx, tx, expected)
	if err != nil {
		return model.ConfigRevision{}, err
	}
	previousDocument, err := json.Marshal(previous.Config)
	if err != nil {
		return model.ConfigRevision{}, err
	}
	unchanged := bytes.Equal(previousDocument, document) && len(oldSecrets) == len(snapshot.Credentials)
	unchanged = unchanged && len(oldCerts) == len(snapshot.Certificates)
	for name, cert := range snapshot.Certificates {
		old := oldCerts[name]
		if !bytes.Equal(cert.Certificate, old.Certificate) || !bytes.Equal(cert.PrivateKey, old.PrivateKey) {
			unchanged = false
		}
	}
	for name, secret := range snapshot.Credentials {
		if !bytes.Equal(secret, oldSecrets[name]) {
			unchanged = false
		}
	}
	if unchanged {
		return previous, nil
	}
	id := "r_" + rand.Text()
	if _, err := tx.ExecContext(ctx, "INSERT INTO config_revisions(id,parent_id,schema_version,document) VALUES(?,?,?,?)", id, expected, snapshot.Config.SchemaVersion, string(document)); err != nil {
		return model.ConfigRevision{}, err
	}
	for name, secret := range snapshot.Credentials {
		asset := oldAssets[name]
		if asset == "" || !bytes.Equal(secret, oldSecrets[name]) {
			asset = "cred_" + rand.Text()
			if _, err := tx.ExecContext(ctx, "INSERT INTO credential_assets(id,secret) VALUES(?,?)", asset, secret); err != nil {
				return model.ConfigRevision{}, err
			}
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO revision_credentials(revision_id,logical_id,asset_id) VALUES(?,?,?)", id, name, asset); err != nil {
			return model.ConfigRevision{}, err
		}
	}
	for name, cert := range snapshot.Certificates {
		asset := oldCertIDs[name]
		old := oldCerts[name]
		if asset == "" || !bytes.Equal(cert.Certificate, old.Certificate) || !bytes.Equal(cert.PrivateKey, old.PrivateKey) {
			asset = "cert_" + rand.Text()
			if _, err := tx.ExecContext(ctx, "INSERT INTO certificate_assets(id,certificate,private_key) VALUES(?,?,?)", asset, cert.Certificate, cert.PrivateKey); err != nil {
				return model.ConfigRevision{}, err
			}
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO revision_certificates(revision_id,logical_id,asset_id) VALUES(?,?,?)", id, name, asset); err != nil {
			return model.ConfigRevision{}, err
		}
	}
	if err := saveGeoBindings(ctx, tx, id, snapshot.Config.GeoData); err != nil {
		return model.ConfigRevision{}, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE config_heads SET draft_revision=? WHERE id=1", id); err != nil {
		return model.ConfigRevision{}, err
	}
	result, err := revision(ctx, tx, id)
	if err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	return result, nil
}

func revision(ctx context.Context, q queryer, id string) (model.ConfigRevision, error) {
	var result model.ConfigRevision
	var parent sql.NullString
	var document string
	err := q.QueryRowContext(ctx, "SELECT id,parent_id,created_at,document FROM config_revisions WHERE id=?", id).Scan(&result.ID, &parent, &result.CreatedAt, &document)
	if errors.Is(err, sql.ErrNoRows) {
		return result, ports.ErrNotFound
	}
	if err != nil {
		return result, err
	}
	result.ParentID = parent.String
	// The original r0 revision predates explicit runtime limits.
	result.Config.Limits = model.DefaultLimits()
	decoder := json.NewDecoder(bytes.NewBufferString(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result.Config); err != nil {
		return result, errors.New("stored configuration document is invalid")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return result, errors.New("stored configuration has trailing data")
	}
	result.CredentialAssets, err = bindingIDs(ctx, q, id)
	if err == nil {
		result.CertificateAssets, err = certificateIDs(ctx, q, id)
	}
	if err == nil {
		err = checkRevisionGeoBindings(ctx, q, id, result.Config.GeoData)
	}
	return result, err
}

func (s *Store) Revision(ctx context.Context, id string) (model.ConfigRevision, error) {
	return revision(ctx, s.db, id)
}

func (s *Store) Resolve(ctx context.Context, id string) (*model.RuntimeConfig, error) {
	revision, err := s.Revision(ctx, id)
	if err != nil {
		return nil, err
	}
	_, secrets, err := bindings(ctx, s.db, id)
	if err != nil {
		return nil, err
	}
	_, certs, err := certificateBindings(ctx, s.db, id)
	if err != nil {
		return nil, err
	}
	for _, listener := range revision.Config.Listeners {
		if listener.CertificateRef != "" {
			if _, ok := certs[listener.CertificateRef]; !ok {
				return nil, errors.New("unresolved stored certificate")
			}
		}
		for _, ref := range listener.CredentialRefs {
			if _, ok := secrets[ref]; !ok {
				return nil, fmt.Errorf("stored listener %q has an unresolved credential", listener.ID)
			}
		}
	}
	geodata, err := resolveGeoData(ctx, s.db, revision.Config.GeoData)
	if err != nil {
		return nil, err
	}
	return &model.RuntimeConfig{Config: revision.Config, Credentials: secrets, Certificates: certs, GeoData: geodata}, nil
}

func (s *Store) Revisions(ctx context.Context, limit int) ([]model.ConfigRevision, error) {
	if limit < 1 || limit > 100 {
		return nil, errors.New("revision limit must be between 1 and 100")
	}
	rows, err := s.db.QueryContext(ctx, "SELECT id FROM config_revisions ORDER BY created_at DESC, id DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	result := make([]model.ConfigRevision, 0, len(ids))
	for _, id := range ids {
		rev, err := s.Revision(ctx, id)
		if err != nil {
			return nil, err
		}
		result = append(result, rev)
	}
	return result, nil
}
