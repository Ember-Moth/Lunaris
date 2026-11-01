// SPDX-License-Identifier: GPL-3.0-only
package config

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/node"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	ports "github.com/Ember-Moth/Lunaris/internal/store"
)

var (
	ErrPersistenceUncertain  = errors.New("persistence outcome is uncertain; restart the managed node before further changes")
	ErrStoredOperationFailed = errors.New("stored application did not succeed; use a new request key to retry")
)

const persistenceTimeout = 5 * time.Second

type Service struct {
	ctx             context.Context
	cancel          context.CancelFunc
	repository      ports.Repository
	registry        *protocol.Registry
	runtime         *node.Runtime
	release         func()
	gate            chan struct{}
	mu              sync.RWMutex
	closed, blocked bool
	applying        bool
	blockReason     string
	actual          *model.RuntimeConfig
	activeRevision  string
	knownHeads      model.ConfigHeads
	mode            string
}

type ServiceStatus struct {
	Mode            string            `json:"mode"`
	Heads           model.ConfigHeads `json:"heads"`
	HeadsKnown      bool              `json:"heads_known"`
	RuntimeRevision string            `json:"runtime_revision"`
	Provisional     bool              `json:"provisional"`
	WritesBlocked   bool              `json:"writes_blocked"`
	Applying        bool              `json:"applying"`
	BlockReason     string            `json:"block_reason,omitempty"`
	Runtime         node.Status       `json:"runtime"`
}

// OpenService restores only the committed revision in managed mode. Offline
// mode starts empty so an invalid old binding cannot prevent an explicit repair.
func OpenService(ctx context.Context, repository ports.Repository, registry *protocol.Registry, restore bool) (*Service, error) {
	if ctx == nil || repository == nil || registry == nil {
		return nil, errors.New("configuration service dependencies are required")
	}
	release, err := repository.ClaimService()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	fail := func(err error) (*Service, error) { cancel(); release(); return nil, err }
	heads, err := repository.Heads(ctx)
	if err != nil {
		return fail(err)
	}
	initial := &model.RuntimeConfig{Config: model.NodeConfig{SchemaVersion: model.ConfigSchemaVersion, Limits: model.DefaultLimits(), Listeners: []model.ListenerSpec{}}, Credentials: map[string][]byte{}}
	mode, active := "offline", ""
	if restore {
		initial, err = repository.Resolve(ctx, heads.CommittedRevision)
		if err != nil {
			return fail(err)
		}
		mode, active = "managed", heads.CommittedRevision
	}
	initial, err = registry.Normalize(initial)
	if err != nil {
		return fail(err)
	}
	runtime, err := node.Start(ctx, initial, registry, nil)
	if err != nil {
		return fail(fmt.Errorf("restore committed configuration: %w", err))
	}
	return &Service{ctx: ctx, cancel: cancel, repository: repository, registry: registry, runtime: runtime, release: release, gate: make(chan struct{}, 1), actual: initial, activeRevision: active, knownHeads: heads, mode: mode}, nil
}

func (s *Service) enter(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case s.gate <- struct{}{}:
	default:
		return ports.ErrBusy
	}
	s.mu.RLock()
	closed := s.closed
	s.mu.RUnlock()
	if closed || s.ctx.Err() != nil {
		<-s.gate
		return node.ErrClosed
	}
	return nil
}

func (s *Service) writable() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.blocked {
		return ErrPersistenceUncertain
	}
	if s.runtime.Snapshot().RecoveryRequired {
		return node.ErrRecoveryRequired
	}
	return nil
}

func (s *Service) workContext(ctx context.Context) (context.Context, func()) {
	work, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.ctx, cancel)
	return work, func() { stop(); cancel() }
}

func (s *Service) SaveDraft(ctx context.Context, expected string, input *model.RuntimeConfig) (model.ConfigRevision, error) {
	if err := s.enter(ctx); err != nil {
		return model.ConfigRevision{}, err
	}
	defer func() { <-s.gate }()
	if err := s.writable(); err != nil {
		return model.ConfigRevision{}, err
	}
	normalized, err := s.registry.Normalize(input)
	if err != nil {
		return model.ConfigRevision{}, err
	}
	work, cancel := s.workContext(ctx)
	defer cancel()
	revision, err := s.repository.SaveDraft(work, expected, normalized)
	if err == nil {
		s.mu.Lock()
		s.knownHeads.DraftRevision = revision.ID
		s.mu.Unlock()
	}
	return revision, err
}

func replayResult(op model.ApplyOperation) (model.ApplyOperation, error) {
	if op.Status == "succeeded" {
		return op, nil
	}
	if !op.Terminal() {
		return op, ports.ErrBusy
	}
	return op, fmt.Errorf("%w: %s (%s)", ErrStoredOperationFailed, op.ID, op.Status)
}

func (s *Service) Apply(ctx context.Context, key, target, expectedBase string) (model.ApplyOperation, error) {
	if err := s.enter(ctx); err != nil {
		return model.ApplyOperation{}, err
	}
	defer func() { <-s.gate }()
	work, cancel := s.workContext(ctx)
	defer cancel()
	prior, err := s.repository.Operation(work, key)
	if err == nil {
		if err := ports.CheckReplay(prior, target, expectedBase); err != nil {
			return prior, err
		}
		if !prior.Terminal() {
			if err := s.writable(); err != nil {
				return prior, err
			}
		}
		return replayResult(prior)
	}
	if !errors.Is(err, ports.ErrNotFound) {
		return model.ApplyOperation{}, err
	}
	if err := s.writable(); err != nil {
		return model.ApplyOperation{}, err
	}
	snapshot, err := s.repository.Resolve(work, target)
	if err != nil {
		return model.ApplyOperation{}, err
	}
	snapshot, err = s.registry.Normalize(snapshot)
	if err != nil {
		return model.ApplyOperation{}, err
	}
	op, replayed, err := s.repository.BeginApply(work, key, target, expectedBase)
	if err != nil {
		return s.admissionFailure(op, key, target, expectedBase, err)
	}
	if replayed {
		return replayResult(op)
	}
	s.mu.Lock()
	s.applying = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.applying = false; s.mu.Unlock() }()
	s.mu.RLock()
	baseline := s.actual
	oldActive := s.activeRevision
	s.mu.RUnlock()
	if err := s.repository.SetPhase(work, op.ID, "applying"); err != nil {
		return s.finishFailure(op, "interrupted", "operation could not begin", err)
	}
	result, applyErr := s.runtime.Apply(work, snapshot)
	if applyErr != nil {
		status := "failed"
		switch result.Outcome {
		case "rolled_back":
			status = "failed_rolled_back"
		case "degraded":
			status = "degraded"
		case "interrupted":
			status = "interrupted"
		}
		if s.runtime.Snapshot().RecoveryRequired {
			s.block("runtime resources could not be released")
		}
		return s.finishFailure(op, status, "runtime application did not complete: "+result.Outcome, applyErr)
	}
	s.mu.Lock()
	s.actual = snapshot
	s.activeRevision = target
	s.mu.Unlock()
	if err := s.repository.SetPhase(work, op.ID, "committing"); err != nil {
		return s.commitFailure(op, baseline, oldActive, err)
	}
	committed, err := s.repository.CommitApply(work, op.ID)
	if err != nil {
		return s.commitFailure(op, baseline, oldActive, err)
	}
	s.confirm(committed)
	return committed, nil
}

func (s *Service) admissionFailure(op model.ApplyOperation, key, target, expectedBase string, cause error) (model.ApplyOperation, error) {
	if errors.Is(cause, ports.ErrBusy) || errors.Is(cause, ports.ErrConflict) || errors.Is(cause, ports.ErrIdempotencyConflict) {
		return op, cause
	}
	check, cancel := context.WithTimeout(context.Background(), persistenceTimeout)
	defer cancel()
	observed, err := s.repository.Operation(check, key)
	if errors.Is(err, ports.ErrNotFound) {
		return op, cause
	}
	if err != nil {
		s.block("operation admission outcome is unknown")
		return op, errors.Join(cause, ErrPersistenceUncertain)
	}
	if err := ports.CheckReplay(observed, target, expectedBase); err != nil {
		return observed, err
	}
	if observed.Terminal() {
		return replayResult(observed)
	}
	return s.finishFailure(observed, "interrupted", "admission did not complete; runtime was not changed", cause)
}

func (s *Service) confirm(op model.ApplyOperation) {
	s.mu.Lock()
	s.knownHeads.CommittedRevision = op.TargetRevision
	s.knownHeads.DraftRevision = op.TargetRevision
	s.activeRevision = op.TargetRevision
	s.mu.Unlock()
}

func (s *Service) block(reason string) {
	s.mu.Lock()
	s.blocked = true
	s.blockReason = reason
	s.mu.Unlock()
}

func (s *Service) finishFailure(op model.ApplyOperation, status, message string, cause error) (model.ApplyOperation, error) {
	cleanup, cancel := context.WithTimeout(context.Background(), persistenceTimeout)
	defer cancel()
	finished, err := s.repository.FinishApply(cleanup, op.ID, status, message)
	if err != nil {
		// A terminal update can itself have committed before its response failed.
		verify, stop := context.WithTimeout(context.Background(), persistenceTimeout)
		defer stop()
		observed, readErr := s.repository.Operation(verify, op.RequestKey)
		if readErr == nil && observed.Status == status {
			return observed, cause
		}
		s.block("operation outcome could not be persisted")
		op.Status = "uncertain"
		op.Phase = "finished"
		op.Error = "operation outcome could not be persisted"
		return op, errors.Join(cause, ErrPersistenceUncertain, err)
	}
	return finished, cause
}

func (s *Service) commitFailure(op model.ApplyOperation, baseline *model.RuntimeConfig, oldActive string, cause error) (model.ApplyOperation, error) {
	check, cancel := context.WithTimeout(context.Background(), persistenceTimeout)
	defer cancel()
	observed, opErr := s.repository.Operation(check, op.RequestKey)
	heads, headErr := s.repository.Heads(check)
	if opErr == nil && headErr == nil && observed.Status == "succeeded" && heads.CommittedRevision == op.TargetRevision {
		s.confirm(observed)
		return observed, nil
	}
	if opErr != nil || headErr != nil || observed.Status != "running" || heads.CommittedRevision != op.BaseRevision {
		s.block("commit outcome is unknown; runtime was not guessed backward")
		op.Status = "uncertain"
		op.Phase = "committing"
		op.Error = "commit outcome is unknown"
		return op, errors.Join(ErrPersistenceUncertain, cause)
	}
	if s.ctx.Err() != nil {
		return s.finishFailure(op, "interrupted", "node stopped before persistence commit", cause)
	}
	cleanup, stop := context.WithTimeout(s.ctx, s.runtime.ShutdownTimeout())
	defer stop()
	_, restoreErr := s.runtime.Apply(cleanup, baseline)
	if restoreErr != nil {
		// P2 can compensate a failed restore back to the uncommitted target.
		// That target must not remain silently active after a known SQL failure.
		closeCtx, closeCancel := context.WithTimeout(context.Background(), s.runtime.ShutdownTimeout())
		defer closeCancel()
		closeErr := s.runtime.Close(closeCtx)
		s.block("runtime could not be restored after persistence failure")
		return s.finishFailure(op, "degraded", "persistence failed and runtime recovery failed", errors.Join(cause, restoreErr, closeErr))
	}
	s.mu.Lock()
	s.actual = baseline
	s.activeRevision = oldActive
	s.mu.Unlock()
	return s.finishFailure(op, "failed_rolled_back", "persistence failed; runtime restored", cause)
}

func (s *Service) Status(ctx context.Context) (ServiceStatus, error) {
	s.mu.RLock()
	status := ServiceStatus{Mode: s.mode, Heads: s.knownHeads, RuntimeRevision: s.activeRevision, WritesBlocked: s.blocked || s.closed, Applying: s.applying, BlockReason: s.blockReason}
	s.mu.RUnlock()
	heads, err := s.repository.Heads(ctx)
	if err == nil {
		status.Heads = heads
		status.HeadsKnown = true
	}
	status.Runtime = s.runtime.Snapshot()
	status.WritesBlocked = status.WritesBlocked || status.Runtime.RecoveryRequired
	status.Provisional = !status.HeadsKnown || status.RuntimeRevision != status.Heads.CommittedRevision
	return status, err
}

func (s *Service) Errors() <-chan error { return s.runtime.Errors() }
func (s *Service) ShutdownTimeout() time.Duration {
	return s.runtime.ShutdownTimeout() + persistenceTimeout
}

func (s *Service) Close(ctx context.Context) error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.cancel()
	select {
	case s.gate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-s.gate }()
	if err := s.runtime.Close(ctx); err != nil {
		return err
	}
	s.release()
	return nil
}
