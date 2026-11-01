// SPDX-License-Identifier: GPL-3.0-only
package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"

	"github.com/Ember-Moth/Lunaris/internal/model"
	ports "github.com/Ember-Moth/Lunaris/internal/store"
)

const operationColumns = "id,request_key,request_digest,expected_base,target_revision,base_revision,status,phase,error_message,created_at,updated_at"

type scanner interface{ Scan(...any) error }

func scanOperation(row scanner) (model.ApplyOperation, error) {
	var o model.ApplyOperation
	err := row.Scan(&o.ID, &o.RequestKey, &o.RequestDigest, &o.ExpectedBase, &o.TargetRevision, &o.BaseRevision, &o.Status, &o.Phase, &o.Error, &o.CreatedAt, &o.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		err = ports.ErrNotFound
	}
	return o, err
}

func (s *Store) Operation(ctx context.Context, key string) (model.ApplyOperation, error) {
	return scanOperation(s.db.QueryRowContext(ctx, "SELECT "+operationColumns+" FROM apply_operations WHERE request_key=?", key))
}

func (s *Store) operationID(ctx context.Context, id string) (model.ApplyOperation, error) {
	return scanOperation(s.db.QueryRowContext(ctx, "SELECT "+operationColumns+" FROM apply_operations WHERE id=?", id))
}

func (s *Store) BeginApply(ctx context.Context, key, target, expectedBase string) (model.ApplyOperation, bool, error) {
	if len(key) == 0 || len(key) > 128 || target == "" {
		return model.ApplyOperation{}, false, errors.New("request key (1-128 bytes) and target revision are required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.ApplyOperation{}, false, err
	}
	defer tx.Rollback()
	digest := ports.RequestDigest(target, expectedBase)
	prior, err := scanOperation(tx.QueryRowContext(ctx, "SELECT "+operationColumns+" FROM apply_operations WHERE request_key=?", key))
	if err == nil {
		if prior.RequestDigest != digest {
			return prior, true, ports.ErrIdempotencyConflict
		}
		return prior, true, nil
	}
	if !errors.Is(err, ports.ErrNotFound) {
		return model.ApplyOperation{}, false, err
	}
	if err := noRunningOperation(ctx, tx); err != nil {
		return model.ApplyOperation{}, false, err
	}
	current, err := heads(ctx, tx)
	if err != nil {
		return model.ApplyOperation{}, false, err
	}
	if current.DraftRevision != target || (expectedBase != "" && expectedBase != current.CommittedRevision) {
		return model.ApplyOperation{}, false, ports.ErrConflict
	}
	id := "op_" + rand.Text()
	_, err = tx.ExecContext(ctx, `INSERT INTO apply_operations(id,request_key,request_digest,expected_base,target_revision,base_revision,status,phase)
		VALUES(?,?,?,?,?,?,'running','accepted')`, id, key, digest, expectedBase, target, current.CommittedRevision)
	if err != nil {
		return model.ApplyOperation{}, false, err
	}
	operation, err := scanOperation(tx.QueryRowContext(ctx, "SELECT "+operationColumns+" FROM apply_operations WHERE id=?", id))
	if err != nil {
		return operation, false, err
	}
	if err := tx.Commit(); err != nil {
		return operation, false, err
	}
	return operation, false, nil
}

func (s *Store) SetPhase(ctx context.Context, id, phase string) error {
	if phase != "applying" && phase != "committing" {
		return errors.New("invalid operation phase")
	}
	result, err := s.db.ExecContext(ctx, "UPDATE apply_operations SET phase=?,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=? AND status='running'", phase, id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ports.ErrConflict
	}
	return nil
}

func (s *Store) CommitApply(ctx context.Context, id string) (model.ApplyOperation, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.ApplyOperation{}, err
	}
	defer tx.Rollback()
	op, err := scanOperation(tx.QueryRowContext(ctx, "SELECT "+operationColumns+" FROM apply_operations WHERE id=?", id))
	if err != nil {
		return op, err
	}
	if op.Status != "running" {
		return op, ports.ErrConflict
	}
	current, err := heads(ctx, tx)
	if err != nil {
		return op, err
	}
	if current.CommittedRevision != op.BaseRevision || current.DraftRevision != op.TargetRevision {
		return op, ports.ErrConflict
	}
	if _, err := tx.ExecContext(ctx, "UPDATE config_heads SET committed_revision=? WHERE id=1", op.TargetRevision); err != nil {
		return op, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE apply_operations SET status='succeeded',phase='finished',error_message='',updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?", id); err != nil {
		return op, err
	}
	op, err = scanOperation(tx.QueryRowContext(ctx, "SELECT "+operationColumns+" FROM apply_operations WHERE id=?", id))
	if err != nil {
		return op, err
	}
	if err := tx.Commit(); err != nil {
		return op, err
	}
	return op, nil
}

func (s *Store) FinishApply(ctx context.Context, id, status, message string) (model.ApplyOperation, error) {
	switch status {
	case "failed", "failed_rolled_back", "degraded", "interrupted":
	default:
		return model.ApplyOperation{}, errors.New("invalid terminal operation status")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.ApplyOperation{}, err
	}
	defer tx.Rollback()
	op, err := scanOperation(tx.QueryRowContext(ctx, "SELECT "+operationColumns+" FROM apply_operations WHERE id=?", id))
	if err != nil {
		return op, err
	}
	if op.Status != "running" {
		return op, ports.ErrConflict
	}
	current, err := heads(ctx, tx)
	if err != nil {
		return op, err
	}
	if current.CommittedRevision != op.BaseRevision {
		return op, ports.ErrConflict
	}
	if _, err := tx.ExecContext(ctx, "UPDATE apply_operations SET status=?,phase='finished',error_message=?,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?", status, message, id); err != nil {
		return op, err
	}
	op, err = scanOperation(tx.QueryRowContext(ctx, "SELECT "+operationColumns+" FROM apply_operations WHERE id=?", id))
	if err != nil {
		return op, err
	}
	if err := tx.Commit(); err != nil {
		return op, err
	}
	return op, nil
}

func (s *Store) recoverOperations(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "UPDATE apply_operations SET status='interrupted',phase='finished',error_message='process stopped during ' || phase || ' before a durable result was recorded',updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE status='running'")
	return err
}

func (s *Store) Operations(ctx context.Context, limit int) ([]model.ApplyOperation, error) {
	if limit < 1 || limit > 100 {
		return nil, errors.New("operation limit must be between 1 and 100")
	}
	rows, err := s.db.QueryContext(ctx, "SELECT "+operationColumns+" FROM apply_operations ORDER BY created_at DESC, id DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]model.ApplyOperation, 0)
	for rows.Next() {
		op, err := scanOperation(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, op)
	}
	return result, rows.Err()
}
