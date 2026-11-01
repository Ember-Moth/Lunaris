// SPDX-License-Identifier: GPL-3.0-only
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"

	"github.com/Ember-Moth/Lunaris/internal/model"
	_ "modernc.org/sqlite"
)

type Store struct {
	db            *sql.DB
	lock          *os.File
	once          sync.Once
	closeErr      error
	dir           string
	serviceMu     sync.Mutex
	serviceActive bool
	closing       bool
}

func Open(ctx context.Context, dataDir string) (_ *Store, err error) {
	dir, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, err
	}
	if err := ensureDataDir(dir); err != nil {
		return nil, err
	}
	lock, err := acquireLock(filepath.Join(dir, "lunaris.lock"))
	if err != nil {
		return nil, err
	}
	store := &Store{lock: lock, dir: dir}
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
	info, statErr := file.Stat()
	if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		file.Close()
		return nil, fmt.Errorf("database must be a private regular file")
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	dsn := url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	query := dsn.Query()
	for _, pragma := range []string{"busy_timeout(5000)", "foreign_keys(1)", "journal_mode(WAL)", "synchronous(FULL)", "trusted_schema(OFF)"} {
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
	if err = validateDatabase(ctx, store.db); err != nil {
		return nil, fmt.Errorf("validate database: %w", err)
	}
	if err = store.recoverOperations(ctx); err != nil {
		return nil, fmt.Errorf("recover operation journal: %w", err)
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
	s.serviceMu.Lock()
	if s.serviceActive {
		s.serviceMu.Unlock()
		return errors.New("close the configuration service before the store")
	}
	s.closing = true
	s.serviceMu.Unlock()
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

func (s *Store) ClaimService() (func(), error) {
	s.serviceMu.Lock()
	defer s.serviceMu.Unlock()
	if s.closing || s.serviceActive {
		return nil, errors.New("store already owned by a configuration service or closed")
	}
	s.serviceActive = true
	var once sync.Once
	return func() { once.Do(func() { s.serviceMu.Lock(); s.serviceActive = false; s.serviceMu.Unlock() }) }, nil
}
