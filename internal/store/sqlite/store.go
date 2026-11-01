// SPDX-License-Identifier: GPL-3.0-only
package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/migrations"
	_ "modernc.org/sqlite"
)

type Store struct {
	db       *sql.DB
	lock     *os.File
	once     sync.Once
	closeErr error
}

func Open(ctx context.Context, dataDir string) (_ *Store, err error) {
	dir, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	lock, err := acquireLock(filepath.Join(dir, "lunaris.lock"))
	if err != nil {
		return nil, err
	}
	store := &Store{lock: lock}
	defer func() {
		if err != nil {
			store.Close()
		}
	}()
	path := filepath.Join(dir, "lunaris.db")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	dsn := url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	query := dsn.Query()
	for _, pragma := range []string{"busy_timeout(5000)", "foreign_keys(1)", "journal_mode(WAL)", "synchronous(FULL)"} {
		query.Add("_pragma", pragma)
	}
	dsn.RawQuery = query.Encode()
	store.db, err = sql.Open("sqlite", dsn.String())
	if err != nil {
		return nil, err
	}
	store.db.SetMaxOpenConns(1)
	if err = store.db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err = store.migrate(ctx); err != nil {
		return nil, fmt.Errorf("migrate database: %w", err)
	}
	return store, nil
}

func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func (s *Store) Heads(ctx context.Context) (model.ConfigHeads, error) {
	var heads model.ConfigHeads
	err := s.db.QueryRowContext(ctx, "SELECT draft_revision, committed_revision FROM config_heads WHERE id = 1").Scan(&heads.DraftRevision, &heads.CommittedRevision)
	return heads, err
}

func (s *Store) Close() error {
	s.once.Do(func() {
		if s.db != nil {
			s.closeErr = s.db.Close()
		}
		if s.lock != nil {
			s.closeErr = errors.Join(s.closeErr, s.lock.Close())
		}
	})
	return s.closeErr
}

func (s *Store) migrate(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		name TEXT PRIMARY KEY, checksum TEXT NOT NULL,
		applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
	)`); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, "SELECT name, checksum FROM schema_migrations ORDER BY name")
	if err != nil {
		return err
	}
	applied := make(map[string]string)
	for rows.Next() {
		var name, checksum string
		if err = rows.Scan(&name, &checksum); err != nil {
			rows.Close()
			return err
		}
		applied[name] = checksum
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	entries, err := migrations.Files.ReadDir(".")
	if err != nil {
		return err
	}
	known := make(map[string]string)
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".sql") {
			content, readErr := migrations.Files.ReadFile(entry.Name())
			if readErr != nil {
				return readErr
			}
			known[entry.Name()] = fmt.Sprintf("%x", sha256.Sum256(content))
		}
	}
	for name, checksum := range applied {
		if known[name] != checksum {
			return fmt.Errorf("unknown or changed applied migration %q", name)
		}
	}
	for _, entry := range entries {
		name := entry.Name()
		if _, ok := known[name]; !ok {
			continue
		}
		if _, done := applied[name]; done {
			continue
		}
		content, err := migrations.Files.ReadFile(name)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, string(content)); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO schema_migrations(name, checksum) VALUES (?, ?)", name, known[name]); err != nil {
			return err
		}
	}
	return tx.Commit()
}
