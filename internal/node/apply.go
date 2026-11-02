// SPDX-License-Identifier: GPL-3.0-only
package node

import (
	"context"
	"errors"
	"fmt"

	"github.com/Ember-Moth/Lunaris/internal/model"
)

type ApplyResult struct {
	Outcome  string `json:"outcome"`
	Revision uint64 `json:"revision"`
	Plan     Plan   `json:"plan"`
}

type ApplyError struct{ Cause, Rollback error }

func (e *ApplyError) Error() string {
	if e.Rollback != nil {
		return fmt.Sprintf("configuration application failed: %v; recovery: %v", e.Cause, e.Rollback)
	}
	return fmt.Sprintf("configuration application failed: %v", e.Cause)
}
func (e *ApplyError) Unwrap() []error {
	var result []error
	if e.Cause != nil {
		result = append(result, e.Cause)
	}
	if e.Rollback != nil {
		result = append(result, e.Rollback)
	}
	return result
}

var ErrStalePlan = errors.New("runtime topology changed since preview")

// Apply performs in-memory, compensating reconfiguration. Durable revision
// transactions are coordinated by the configuration service.
func (r *Runtime) Apply(ctx context.Context, input *model.RuntimeConfig) (ApplyResult, error) {
	return r.ApplyExpected(ctx, input, nil)
}

// ApplyExpected rejects an outdated preview before replacing active listeners.
func (r *Runtime) ApplyExpected(ctx context.Context, input *model.RuntimeConfig, expectedEpoch *uint64) (result ApplyResult, err error) {
	result.Outcome = "rejected"
	if ctx == nil {
		return result, errors.New("apply context is required")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	select {
	case r.gate <- struct{}{}:
	default:
		return result, ErrBusy
	}
	defer func() { <-r.gate }()
	r.mu.Lock()
	if r.closed || r.ctx.Err() != nil {
		r.mu.Unlock()
		return result, ErrClosed
	}
	if r.blocked {
		r.mu.Unlock()
		return result, ErrRecoveryRequired
	}
	if expectedEpoch != nil && r.epoch != *expectedEpoch {
		r.mu.Unlock()
		return result, ErrStalePlan
	}
	r.applying = true
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.applying = false
		result.Revision = r.revision
		r.lastOutcome = result.Outcome
		r.lastApplyError = ""
		if err != nil {
			r.lastApplyError = err.Error()
		}
		r.mu.Unlock()
	}()
	target, err := r.registry.Normalize(input)
	if err != nil {
		return result, err
	}
	r.mu.RLock()
	base := r.config
	result.Plan = r.planLocked(target)
	r.mu.RUnlock()
	if !result.Plan.ContentChanged && !result.Plan.changesRuntime() {
		result.Outcome = "no_change"
		return result, nil
	}
	work, cancel := context.WithCancel(ctx)
	stopRoot := context.AfterFunc(r.ctx, cancel)
	defer cancel()
	defer stopRoot()
	wanted := specs(target)
	candidates := make([]*record, 0)
	byID := make(map[string]*record)
	for _, change := range result.Plan.Changes {
		if change.Action != "create" && change.Action != "replace" && change.Action != "recover" {
			continue
		}
		if err = work.Err(); err != nil {
			break
		}
		var rec *record
		rec, err = r.build(target, wanted[change.ID])
		if rec != nil {
			candidates = append(candidates, rec)
			byID[change.ID] = rec
		}
		if err != nil {
			break
		}
	}
	if err != nil {
		cleanup, stop := context.WithTimeout(context.Background(), r.timeout())
		defer stop()
		recovery := r.cleanupCandidates(cleanup, candidates)
		r.markUnreleased()
		if recovery != nil {
			result.Outcome = "degraded"
		}
		return result, &ApplyError{Cause: err, Rollback: recovery}
	}
	if expectedEpoch != nil {
		r.mu.RLock()
		stale := r.epoch != *expectedEpoch
		r.mu.RUnlock()
		if stale {
			cleanup, stop := context.WithTimeout(context.Background(), r.timeout())
			defer stop()
			cleanupErr := r.cleanupCandidates(cleanup, candidates)
			r.markUnreleased()
			if cleanupErr != nil {
				result.Outcome = "degraded"
				return result, &ApplyError{Cause: ErrStalePlan, Rollback: cleanupErr}
			}
			return result, ErrStalePlan
		}
	}
	affected := make(map[string]bool)
	old := make([]*record, 0)
	r.mu.RLock()
	for _, change := range result.Plan.Changes {
		if change.Action == "keep" {
			continue
		}
		affected[change.ID] = true
		if rec := r.records[change.ID]; rec != nil {
			old = append(old, rec)
		}
	}
	r.mu.RUnlock()
	stopCtx, stop := context.WithTimeout(work, r.timeout())
	for i := len(old) - 1; i >= 0; i-- {
		if err = r.stopRecord(stopCtx, old[i]); err != nil {
			break
		}
	}
	stop()
	if err == nil {
		err = work.Err()
	}
	if err == nil {
		for _, change := range result.Plan.Changes {
			if rec := byID[change.ID]; rec != nil {
				if err = r.startRecord(work, rec); err != nil {
					break
				}
			}
		}
	}
	if err == nil {
		err = work.Err()
	}
	if err == nil {
		r.mu.Lock()
		if r.closed || r.ctx.Err() != nil {
			err = ErrClosed
		} else if work.Err() != nil {
			err = work.Err()
		} else if !r.healthyLocked(target) {
			err = errors.New("target listeners are not all running")
		} else {
			r.config = target
			if result.Plan.ContentChanged {
				r.revision++
			}
			for id, rec := range r.records {
				if spec, ok := wanted[id]; !ok || !spec.Enabled {
					delete(r.records, id)
				} else {
					rec.provisional = false
				}
			}
			if result.Plan.changesRuntime() {
				r.epoch++
			}
			result.Outcome = "applied"
		}
		r.mu.Unlock()
		if err == nil {
			return result, nil
		}
	}
	if r.ctx.Err() != nil {
		// Process shutdown owns final cleanup; never resurrect a baseline while
		// the entire node is closing. All candidates remain in the owned set.
		result.Outcome = "interrupted"
		return result, err
	}
	recovery := r.rollback(base, affected, old, candidates)
	result.Outcome = "rolled_back"
	if recovery != nil {
		result.Outcome = "degraded"
	}
	return result, &ApplyError{Cause: err, Rollback: recovery}
}

func (r *Runtime) cleanupCandidates(ctx context.Context, candidates []*record) error {
	var result error
	for i := len(candidates) - 1; i >= 0; i-- {
		rec := candidates[i]
		err := r.stopRecord(ctx, rec)
		result = errors.Join(result, err)
		if err == nil {
			r.mu.Lock()
			if r.records[rec.spec.ID] == rec {
				delete(r.records, rec.spec.ID)
			}
			r.mu.Unlock()
		}
	}
	return result
}

func (r *Runtime) markUnreleased() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for rec := range r.owned {
		if rec.retiring {
			r.blocked = true
		}
	}
}

func (r *Runtime) rollback(base *model.RuntimeConfig, affected map[string]bool, old, candidates []*record) error {
	cleanup, stop := context.WithTimeout(r.ctx, r.timeout())
	defer stop()
	result := r.cleanupCandidates(cleanup, candidates)
	// Retry interrupted stops with a fresh recovery context before deciding
	// that the old resource cannot safely be replaced.
	for _, rec := range old {
		r.mu.RLock()
		_, owned := r.owned[rec]
		r.mu.RUnlock()
		if owned {
			result = errors.Join(result, r.stopRecord(cleanup, rec))
		}
	}
	r.markUnreleased()
	baseline := specs(base)
	for _, rec := range old {
		// A confirmed stopped record is just a status placeholder now.
		r.mu.Lock()
		if rec.state == "stopped" && r.records[rec.spec.ID] == rec {
			delete(r.records, rec.spec.ID)
		}
		r.mu.Unlock()
	}
	if base != nil {
		for _, spec := range base.Config.Listeners {
			if !affected[spec.ID] || !spec.Enabled {
				continue
			}
			r.mu.RLock()
			unreleased := false
			for rec := range r.owned {
				if rec.spec.ID == spec.ID {
					unreleased = true
					break
				}
			}
			r.mu.RUnlock()
			if unreleased {
				result = errors.Join(result, fmt.Errorf("listener %q still owns unreleased resources", spec.ID))
				continue
			}
			if err := cleanup.Err(); err != nil {
				result = errors.Join(result, err)
				break
			}
			restored, err := r.build(base, spec)
			if err == nil {
				err = r.startRecord(cleanup, restored)
			}
			if err != nil {
				result = errors.Join(result, err)
				if restored != nil {
					stopErr := r.stopRecord(cleanup, restored)
					result = errors.Join(result, stopErr)
					// Keep the failed restored record visible for a later recover.
					r.mu.Lock()
					restored.state = "failed"
					restored.lastError = err.Error()
					restored.provisional = false
					r.records[spec.ID] = restored
					r.epoch++
					r.mu.Unlock()
				}
				continue
			}
			r.mu.Lock()
			restored.provisional = false
			r.mu.Unlock()
		}
	}
	r.markUnreleased()
	r.mu.Lock()
	for id, rec := range r.records {
		if _, exists := baseline[id]; !exists && rec.state == "stopped" {
			delete(r.records, id)
		}
	}
	if r.blocked || !r.healthyLocked(base) {
		result = errors.Join(result, errors.New("previous configuration is not fully restored"))
	}
	r.mu.Unlock()
	return result
}
