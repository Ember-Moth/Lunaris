// SPDX-License-Identifier: GPL-3.0-only
package sqlite

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Ember-Moth/Lunaris/migrations"
)

type migration struct {
	name, checksum string
	content        []byte
}

func manifest() ([]migration, error) {
	entries, err := migrations.Files.ReadDir(".")
	if err != nil {
		return nil, err
	}
	result := make([]migration, 0)
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		content, err := migrations.Files.ReadFile(entry.Name())
		if err != nil {
			return nil, err
		}
		result = append(result, migration{name: entry.Name(), checksum: fmt.Sprintf("%x", sha256.Sum256(content)), content: content})
	}
	return result, nil
}

func migrationCount(ctx context.Context, db *sql.DB, known []migration) (int, error) {
	var exists int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name='schema_migrations'").Scan(&exists); err != nil {
		return 0, err
	}
	if exists == 0 {
		var tables int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'").Scan(&tables); err != nil {
			return 0, err
		}
		if tables != 0 {
			return 0, errors.New("unrecognized database: migration history is missing")
		}
		return 0, nil
	}
	rows, err := db.QueryContext(ctx, "SELECT name,checksum FROM schema_migrations ORDER BY name")
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var name, checksum string
		if err := rows.Scan(&name, &checksum); err != nil {
			return 0, err
		}
		if count >= len(known) || known[count].name != name || known[count].checksum != checksum {
			return 0, fmt.Errorf("unknown, changed or non-contiguous applied migration %q", name)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	rows.Close()
	if count == 0 {
		var otherTables int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name!='schema_migrations'").Scan(&otherTables); err != nil {
			return 0, err
		}
		if otherTables != 0 {
			return 0, errors.New("unrecognized database: empty migration history with existing tables")
		}
	}
	return count, nil
}

func (s *Store) migrate(ctx context.Context) error {
	known, err := manifest()
	if err != nil {
		return err
	}
	count, err := migrationCount(ctx, s.db, known)
	if err != nil {
		return err
	}
	if count == len(known) {
		return nil
	}
	if count > 0 {
		output := filepath.Join(s.dir, "migration-backups", "before-"+known[count].name+"-"+rand.Text()+".db")
		if err := snapshotDatabase(ctx, s.db, output); err != nil {
			return fmt.Errorf("pre-migration backup: %w", err)
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		name TEXT PRIMARY KEY, checksum TEXT NOT NULL,
		applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
	)`); err != nil {
		return err
	}
	for _, entry := range known[count:] {
		if _, err := tx.ExecContext(ctx, string(entry.content)); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations(name,checksum) VALUES(?,?)", entry.name, entry.checksum); err != nil {
			return err
		}
	}
	return tx.Commit()
}
