// SPDX-License-Identifier: GPL-3.0-only
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
)

func ensureDataDir(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		return errors.New("data directory must not be writable by group or others")
	}
	return nil
}

func openReadOnly(ctx context.Context, path string) (*sql.DB, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("database input must be a regular file")
	}
	dsn := url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	q := dsn.Query()
	q.Set("mode", "ro")
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "trusted_schema(OFF)")
	dsn.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", dsn.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func validateDatabase(ctx context.Context, db *sql.DB) error {
	var integrity string
	if err := db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); err != nil {
		return err
	}
	if integrity != "ok" {
		return errors.New("database integrity check failed")
	}
	known, err := manifest()
	if err != nil {
		return err
	}
	count, err := migrationCount(ctx, db, known)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("database has no Lunaris migration history")
	}
	rows, err := db.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return err
	}
	invalid := rows.Next()
	rowErr := rows.Err()
	rows.Close()
	if rowErr != nil {
		return rowErr
	}
	if invalid {
		return errors.New("database foreign key check failed")
	}
	_, err = heads(ctx, db)
	return err
}

// snapshotDatabase includes the WAL through SQLite, syncs a private temporary
// output, then publishes it without overwriting an existing path.
func snapshotDatabase(ctx context.Context, db *sql.DB, destination string) error {
	destination, err := filepath.Abs(destination)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(destination); err == nil {
		return fs.ErrExist
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	dir := filepath.Dir(destination)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".lunaris-backup-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Close(); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, "VACUUM main INTO ?", temporary); err != nil {
		return err
	}
	file, err = os.OpenFile(temporary, os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	err = file.Sync()
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Both paths are in the same directory; Link provides atomic no-clobber
	// publication on the local filesystems supported by the node.
	if err := os.Link(temporary, destination); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

// Backup is offline: it takes the same process lock as the running node. It
// does not migrate or alter the source database before taking the snapshot.
func Backup(ctx context.Context, dataDir, destination string) error {
	dir, err := filepath.Abs(dataDir)
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(dir, "lunaris.db")); err != nil {
		return err
	}
	lock, err := acquireLock(filepath.Join(dir, "lunaris.lock"))
	if err != nil {
		return err
	}
	defer lock.Close()
	db, err := openReadOnly(ctx, filepath.Join(dir, "lunaris.db"))
	if err != nil {
		return err
	}
	defer db.Close()
	if err := validateDatabase(ctx, db); err != nil {
		return err
	}
	return snapshotDatabase(ctx, db, destination)
}

// Restore only accepts an empty destination directory. Validation and creation
// happen before the database path becomes visible; existing node data is never replaced.
func Restore(ctx context.Context, dataDir, source string) error {
	dir, err := filepath.Abs(dataDir)
	if err != nil {
		return err
	}
	if err := ensureDataDir(dir); err != nil {
		return err
	}
	lock, err := acquireLock(filepath.Join(dir, "lunaris.lock"))
	if err != nil {
		return err
	}
	defer lock.Close()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() != "lunaris.lock" {
			return errors.New("restore destination must be empty")
		}
	}
	db, err := openReadOnly(ctx, source)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := validateDatabase(ctx, db); err != nil {
		return fmt.Errorf("invalid backup: %w", err)
	}
	return snapshotDatabase(ctx, db, filepath.Join(dir, "lunaris.db"))
}
