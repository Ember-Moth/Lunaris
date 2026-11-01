// SPDX-License-Identifier: GPL-3.0-only
package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/Ember-Moth/Lunaris/internal/model"
)

func RequestDigest(target, base string) string {
	data, _ := json.Marshal([]string{target, base})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func CheckReplay(operation model.ApplyOperation, target, base string) error {
	if operation.TargetRevision != target || operation.ExpectedBase != base || operation.RequestDigest != RequestDigest(target, base) {
		return ErrIdempotencyConflict
	}
	return nil
}

var (
	ErrNotFound            = errors.New("stored resource not found")
	ErrConflict            = errors.New("configuration revision conflict")
	ErrBusy                = errors.New("a configuration application is already running")
	ErrIdempotencyConflict = errors.New("request key was already used for a different operation")
)

// Repository is the persistence port of the configuration application service.
// Successful CommitApply atomically advances the committed head and the operation.
type Repository interface {
	ClaimService() (func(), error)
	Heads(context.Context) (model.ConfigHeads, error)
	SaveDraft(context.Context, string, *model.RuntimeConfig) (model.ConfigRevision, error)
	Revision(context.Context, string) (model.ConfigRevision, error)
	Resolve(context.Context, string) (*model.RuntimeConfig, error)
	Operation(context.Context, string) (model.ApplyOperation, error)
	BeginApply(context.Context, string, string, string) (model.ApplyOperation, bool, error)
	SetPhase(context.Context, string, string) error
	CommitApply(context.Context, string) (model.ApplyOperation, error)
	FinishApply(context.Context, string, string, string) (model.ApplyOperation, error)
}
