// SPDX-License-Identifier: GPL-3.0-only
package sqlite

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"errors"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/auth"
	"github.com/Ember-Moth/Lunaris/internal/model"
	ports "github.com/Ember-Moth/Lunaris/internal/store"
)

func (s *Store) AuthSetupState(ctx context.Context) (auth.SetupState, error) {
	var state auth.SetupState
	var expiry int64
	err := s.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM admin_account),setup_token_hash,setup_expires FROM installation WHERE id=1").Scan(&state.Initialized, &state.TokenHash, &expiry)
	state.ExpiresAt = time.Unix(expiry, 0).UTC()
	return state, err
}
func (s *Store) SetSetupToken(ctx context.Context, hash string, expires time.Time, replace bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var count int
	var prior string
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM admin_account").Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return auth.ErrInitialized
	}
	if err = tx.QueryRowContext(ctx, "SELECT setup_token_hash FROM installation WHERE id=1").Scan(&prior); err != nil {
		return err
	}
	if prior != "" && !replace {
		return ports.ErrConflict
	}
	if _, err = tx.ExecContext(ctx, "UPDATE installation SET setup_token_hash=?,setup_expires=? WHERE id=1", hash, expires.Unix()); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) InitializeAdmin(ctx context.Context, hash, username, passwordHash string, now time.Time) (model.AdminAccount, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.AdminAccount{}, err
	}
	defer tx.Rollback()
	var count int
	var token string
	var expiry int64
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM admin_account").Scan(&count); err != nil {
		return model.AdminAccount{}, err
	}
	if count != 0 {
		return model.AdminAccount{}, auth.ErrInitialized
	}
	if err = tx.QueryRowContext(ctx, "SELECT setup_token_hash,setup_expires FROM installation WHERE id=1").Scan(&token, &expiry); err != nil {
		return model.AdminAccount{}, err
	}
	if expiry <= now.Unix() || len(token) != 64 || subtle.ConstantTimeCompare([]byte(hash), []byte(token)) != 1 {
		return model.AdminAccount{}, auth.ErrAuthentication
	}
	a := model.AdminAccount{ID: "admin_" + rand.Text(), Username: username, PasswordHash: passwordHash, Version: 1}
	if _, err = tx.ExecContext(ctx, "INSERT INTO admin_account(singleton,id,username,password_hash) VALUES(1,?,?,?)", a.ID, a.Username, a.PasswordHash); err != nil {
		return a, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE installation SET setup_token_hash='',setup_expires=0 WHERE id=1"); err != nil {
		return a, err
	}
	return a, tx.Commit()
}
func scanAccount(row scanner) (model.AdminAccount, error) {
	var a model.AdminAccount
	err := row.Scan(&a.ID, &a.Username, &a.PasswordHash, &a.Version)
	if errors.Is(err, sql.ErrNoRows) {
		err = ports.ErrNotFound
	}
	return a, err
}
func (s *Store) AdminAccount(ctx context.Context) (model.AdminAccount, error) {
	return scanAccount(s.db.QueryRowContext(ctx, "SELECT id,username,password_hash,version FROM admin_account WHERE singleton=1"))
}
func (s *Store) CreateAdminSession(ctx context.Context, session model.AdminSession) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	a, err := scanAccount(tx.QueryRowContext(ctx, "SELECT id,username,password_hash,version FROM admin_account WHERE singleton=1"))
	if err != nil {
		return err
	}
	if a.ID != session.AccountID || a.Version != session.AccountVersion {
		return auth.ErrAuthentication
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM admin_sessions WHERE expires_at<=?", session.CreatedAt.Unix()); err != nil {
		return err
	}
	// Retain at most 32 live sessions, even under repeated successful logins.
	if _, err = tx.ExecContext(ctx, "DELETE FROM admin_sessions WHERE token_hash IN (SELECT token_hash FROM admin_sessions ORDER BY created_at DESC,token_hash DESC LIMIT -1 OFFSET 31)"); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO admin_sessions(token_hash,account_id,account_version,csrf_token,expires_at,created_at) VALUES(?,?,?,?,?,?)`, session.TokenHash, session.AccountID, session.AccountVersion, session.CSRFToken, session.ExpiresAt.Unix(), session.CreatedAt.Unix()); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) AdminSession(ctx context.Context, hash string, now time.Time) (model.AdminAccount, model.AdminSession, error) {
	var a model.AdminAccount
	var v model.AdminSession
	var expires, reauth, created int64
	err := s.db.QueryRowContext(ctx, `SELECT a.id,a.username,a.password_hash,a.version,s.token_hash,s.csrf_token,s.expires_at,s.reauth_until,s.created_at
 FROM admin_sessions s JOIN admin_account a ON a.id=s.account_id AND a.version=s.account_version WHERE s.token_hash=? AND s.expires_at>?`, hash, now.Unix()).Scan(&a.ID, &a.Username, &a.PasswordHash, &a.Version, &v.TokenHash, &v.CSRFToken, &expires, &reauth, &created)
	if errors.Is(err, sql.ErrNoRows) {
		err = ports.ErrNotFound
	}
	v.AccountID = a.ID
	v.AccountVersion = a.Version
	v.ExpiresAt = time.Unix(expires, 0).UTC()
	v.ReauthUntil = time.Unix(reauth, 0).UTC()
	v.CreatedAt = time.Unix(created, 0).UTC()
	return a, v, err
}
func (s *Store) RevokeAdminSession(ctx context.Context, hash string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM admin_sessions WHERE token_hash=?", hash)
	return err
}
func (s *Store) ChangeAdminPassword(ctx context.Context, id string, version int64, hash string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "UPDATE admin_account SET password_hash=?,version=version+1 WHERE id=? AND version=?", hash, id, version)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return auth.ErrAuthentication
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM admin_sessions WHERE account_id=?", id); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) GrantReauth(ctx context.Context, hash string, version int64, now, until time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE admin_sessions SET reauth_until=? WHERE token_hash=? AND account_version=? AND expires_at>? AND EXISTS(SELECT 1 FROM admin_account a WHERE a.id=admin_sessions.account_id AND a.version=admin_sessions.account_version)`, until.Unix(), hash, version, now.Unix())
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return auth.ErrAuthentication
	}
	return nil
}
func (s *Store) PurgeAdminSessions(ctx context.Context, now time.Time) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM admin_sessions WHERE expires_at<=? OR NOT EXISTS(SELECT 1 FROM admin_account a WHERE a.id=admin_sessions.account_id AND a.version=admin_sessions.account_version)", now.Unix())
	return err
}
