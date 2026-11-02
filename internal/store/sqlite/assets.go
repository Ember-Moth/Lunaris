// SPDX-License-Identifier: GPL-3.0-only
package sqlite

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"unicode/utf8"

	"github.com/Ember-Moth/Lunaris/internal/model"
	ports "github.com/Ember-Moth/Lunaris/internal/store"
)

func validAssetMetadata(kind, label string) bool {
	return len(kind) <= 64 && len(label) <= 256 && utf8.ValidString(kind) && utf8.ValidString(label)
}
func (s *Store) CreateCredential(ctx context.Context, kind, label string, secret []byte) (model.CredentialAsset, error) {
	if !validAssetMetadata(kind, label) || kind == "" || len(secret) < 1 || len(secret) > 4096 {
		return model.CredentialAsset{}, errors.New("invalid credential asset")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.CredentialAsset{}, err
	}
	defer tx.Rollback()
	if err = noRunningOperation(ctx, tx); err != nil {
		return model.CredentialAsset{}, err
	}
	id := "cred_" + rand.Text()
	if _, err = tx.ExecContext(ctx, "INSERT INTO credential_assets(id,secret,kind,label) VALUES(?,?,?,?)", id, secret, kind, label); err != nil {
		return model.CredentialAsset{}, err
	}
	if err = tx.Commit(); err != nil {
		return model.CredentialAsset{}, err
	}
	return s.Credential(ctx, id)
}
func references(ctx context.Context, q queryer, table, id string) ([]model.AssetReference, error) {
	rows, err := q.QueryContext(ctx, "SELECT revision_id,logical_id FROM "+table+" WHERE asset_id=? ORDER BY revision_id,logical_id LIMIT 100", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	refs := make([]model.AssetReference, 0)
	for rows.Next() {
		var r model.AssetReference
		if err := rows.Scan(&r.Revision, &r.LogicalID); err != nil {
			return nil, err
		}
		refs = append(refs, r)
	}
	return refs, rows.Err()
}
func (s *Store) Credential(ctx context.Context, id string) (model.CredentialAsset, error) {
	var a model.CredentialAsset
	err := s.db.QueryRowContext(ctx, "SELECT id,kind,label,created_at FROM credential_assets WHERE id=?", id).Scan(&a.ID, &a.Kind, &a.Label, &a.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		err = ports.ErrNotFound
	}
	if err != nil {
		return a, err
	}
	a.References, err = references(ctx, s.db, "revision_credentials", id)
	if err == nil {
		err = s.db.QueryRowContext(ctx, "SELECT count(*) FROM revision_credentials WHERE asset_id=?", id).Scan(&a.ReferenceCount)
	}
	a.ReferencesTruncated = a.ReferenceCount > len(a.References)
	return a, err
}
func pageIDs(ctx context.Context, q queryer, table, cursor string, limit int) ([]string, string, error) {
	if limit < 1 || limit > 100 || len(cursor) > 128 {
		return nil, "", errors.New("invalid pagination")
	}
	rows, err := q.QueryContext(ctx, "SELECT id FROM "+table+" WHERE id>? ORDER BY id LIMIT ?", cursor, limit+1)
	if err != nil {
		return nil, "", err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, "", err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, "", err
	}
	next := ""
	if len(ids) > limit {
		ids = ids[:limit]
		next = ids[len(ids)-1]
	}
	return ids, next, nil
}
func (s *Store) Credentials(ctx context.Context, cursor string, limit int) ([]model.CredentialAsset, string, error) {
	ids, next, err := pageIDs(ctx, s.db, "credential_assets", cursor, limit)
	if err != nil {
		return nil, "", err
	}
	result := make([]model.CredentialAsset, 0, len(ids))
	for _, id := range ids {
		a, err := s.Credential(ctx, id)
		if err != nil {
			return nil, "", err
		}
		result = append(result, a)
	}
	return result, next, nil
}
func (s *Store) deleteAsset(ctx context.Context, table, bindings, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = noRunningOperation(ctx, tx); err != nil {
		return err
	}
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM "+bindings+" WHERE asset_id=?", id).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return ports.ErrReferenced
	}
	result, err := tx.ExecContext(ctx, "DELETE FROM "+table+" WHERE id=?", id)
	if err != nil {
		return err
	}
	count64, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count64 != 1 {
		return ports.ErrNotFound
	}
	return tx.Commit()
}
func (s *Store) DeleteCredential(ctx context.Context, id string) error {
	return s.deleteAsset(ctx, "credential_assets", "revision_credentials", id)
}
func (s *Store) CreateCertificate(ctx context.Context, label string, cert model.Certificate) (model.CertificateAsset, error) {
	if !validAssetMetadata("", label) || len(cert.Certificate) > 1<<20 || len(cert.PrivateKey) > 1<<20 {
		return model.CertificateAsset{}, errors.New("invalid certificate asset")
	}
	if _, err := certificateDetails(cert); err != nil {
		return model.CertificateAsset{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.CertificateAsset{}, err
	}
	defer tx.Rollback()
	if err = noRunningOperation(ctx, tx); err != nil {
		return model.CertificateAsset{}, err
	}
	id := "cert_" + rand.Text()
	if _, err = tx.ExecContext(ctx, "INSERT INTO certificate_assets(id,label,certificate,private_key) VALUES(?,?,?,?)", id, label, cert.Certificate, cert.PrivateKey); err != nil {
		return model.CertificateAsset{}, err
	}
	if err = tx.Commit(); err != nil {
		return model.CertificateAsset{}, err
	}
	return s.Certificate(ctx, id)
}
func certificateDetails(c model.Certificate) (model.CertificateAsset, error) {
	pair, err := tls.X509KeyPair(c.Certificate, c.PrivateKey)
	if err != nil || len(pair.Certificate) == 0 {
		return model.CertificateAsset{}, errors.New("invalid certificate and private key pair")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return model.CertificateAsset{}, errors.New("invalid leaf certificate")
	}
	sum := sha256.Sum256(leaf.Raw)
	return model.CertificateAsset{Subject: leaf.Subject.String(), DNSNames: leaf.DNSNames, Fingerprint: hex.EncodeToString(sum[:]), NotBefore: leaf.NotBefore.UTC(), NotAfter: leaf.NotAfter.UTC()}, nil
}
func (s *Store) Certificate(ctx context.Context, id string) (model.CertificateAsset, error) {
	var raw model.Certificate
	var label, created string
	err := s.db.QueryRowContext(ctx, "SELECT label,created_at,certificate FROM certificate_assets WHERE id=?", id).Scan(&label, &created, &raw.Certificate)
	if errors.Is(err, sql.ErrNoRows) {
		err = ports.ErrNotFound
	}
	if err != nil {
		return model.CertificateAsset{}, err
	}
	a, err := publicCertificateDetails(raw.Certificate)
	if err != nil {
		return a, err
	}
	a.ID = id
	a.Label = label
	a.CreatedAt = created
	a.References, err = references(ctx, s.db, "revision_certificates", id)
	if err == nil {
		err = s.db.QueryRowContext(ctx, "SELECT count(*) FROM revision_certificates WHERE asset_id=?", id).Scan(&a.ReferenceCount)
	}
	a.ReferencesTruncated = a.ReferenceCount > len(a.References)
	return a, err
}
func (s *Store) Certificates(ctx context.Context, cursor string, limit int) ([]model.CertificateAsset, string, error) {
	ids, next, err := pageIDs(ctx, s.db, "certificate_assets", cursor, limit)
	if err != nil {
		return nil, "", err
	}
	result := make([]model.CertificateAsset, 0, len(ids))
	for _, id := range ids {
		a, err := s.Certificate(ctx, id)
		if err != nil {
			return nil, "", err
		}
		result = append(result, a)
	}
	return result, next, nil
}
func (s *Store) DeleteCertificate(ctx context.Context, id string) error {
	return s.deleteAsset(ctx, "certificate_assets", "revision_certificates", id)
}
func (s *Store) RevisionPage(ctx context.Context, cursor string, limit int) ([]model.ConfigRevision, string, error) {
	ids, next, err := pageIDs(ctx, s.db, "config_revisions", cursor, limit)
	if err != nil {
		return nil, "", err
	}
	result := make([]model.ConfigRevision, 0, len(ids))
	for _, id := range ids {
		r, err := s.Revision(ctx, id)
		if err != nil {
			return nil, "", err
		}
		result = append(result, r)
	}
	return result, next, nil
}

func publicCertificateDetails(raw []byte) (model.CertificateAsset, error) {
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return model.CertificateAsset{}, errors.New("invalid stored certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return model.CertificateAsset{}, errors.New("invalid stored certificate")
	}
	sum := sha256.Sum256(leaf.Raw)
	return model.CertificateAsset{Subject: leaf.Subject.String(), DNSNames: leaf.DNSNames, Fingerprint: hex.EncodeToString(sum[:]), NotBefore: leaf.NotBefore.UTC(), NotAfter: leaf.NotAfter.UTC()}, nil
}
