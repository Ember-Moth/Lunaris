// SPDX-License-Identifier: GPL-3.0-only
package config

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/node"
	ports "github.com/Ember-Moth/Lunaris/internal/store"
)

var (
	ErrInvalidDraft              = errors.New("invalid managed configuration")
	ErrPlanExpired               = errors.New("application plan is expired or stale")
	ErrDisconnectAcknowledgement = errors.New("connection interruptions must be acknowledged")
	ErrManagementEndpoint        = errors.New("proxy listener conflicts with management endpoint")
)

const planTTL = 2 * time.Minute
const maxPlans = 128
const applyTimeout = 2 * time.Minute

type ApplicationPlan struct {
	ID            string        `json:"plan_id"`
	DraftRevision string        `json:"draft_revision"`
	BaseRevision  string        `json:"base_revision"`
	BootID        string        `json:"boot_id"`
	RuntimeEpoch  uint64        `json:"runtime_epoch"`
	ExpiresAt     time.Time     `json:"expires_at"`
	Changes       []node.Change `json:"changes"`
}

func (s *Service) normalize(input *model.RuntimeConfig) (*model.RuntimeConfig, error) {
	normalized, err := s.registry.Normalize(input)
	if err != nil {
		return nil, err
	}
	if err = checkReserved(normalized, s.reservedTCP); err != nil {
		return nil, err
	}
	return normalized, nil
}
func checkReserved(input *model.RuntimeConfig, reserved []netip.AddrPort) error {
	for _, spec := range input.Config.Listeners {
		if !spec.Enabled || !slices.Contains(spec.Network, "tcp") {
			continue
		}
		ip, err := netip.ParseAddr(spec.Address)
		if err != nil {
			return err
		}
		ip = ip.Unmap()
		for _, endpoint := range reserved {
			if endpoint.Port() == spec.Port && (ip == endpoint.Addr().Unmap() || ip.IsUnspecified() || endpoint.Addr().IsUnspecified()) {
				return ErrManagementEndpoint
			}
		}
	}
	return nil
}
func (s *Service) management() (ports.ManagementRepository, error) {
	r, ok := s.repository.(ports.ManagementRepository)
	if !ok {
		return nil, errors.New("management repository unavailable")
	}
	return r, nil
}
func (s *Service) ValidateDraft(ctx context.Context, input model.DraftInput) (model.DraftInput, error) {
	select {
	case s.validationGate <- struct{}{}:
		defer func() { <-s.validationGate }()
	default:
		return input, ports.ErrBusy
	}
	repo, err := s.management()
	if err != nil {
		return input, err
	}
	snapshot, err := repo.ResolveDraftInput(ctx, input)
	if err != nil {
		if errors.Is(err, ports.ErrNotFound) || errors.Is(err, ports.ErrInvalidInput) {
			return input, ErrInvalidDraft
		}
		return input, err
	}
	normalized, err := s.normalize(snapshot)
	if err != nil {
		return input, ErrInvalidDraft
	}
	input.Config = normalized.Config
	return input, nil
}
func (s *Service) SaveManagedDraft(ctx context.Context, expected string, input model.DraftInput) (model.ConfigRevision, error) {
	if err := s.enter(ctx); err != nil {
		return model.ConfigRevision{}, err
	}
	defer func() { <-s.gate }()
	if err := s.writable(); err != nil {
		return model.ConfigRevision{}, err
	}
	work, cancel := s.workContext(ctx)
	defer cancel()
	input, err := s.ValidateDraft(work, input)
	if err != nil {
		return model.ConfigRevision{}, err
	}
	repo, err := s.management()
	if err != nil {
		return model.ConfigRevision{}, err
	}
	saved, err := repo.SaveDraftReferences(work, expected, input)
	if err == nil {
		s.mu.Lock()
		s.knownHeads.DraftRevision = saved.ID
		clear(s.plans)
		s.mu.Unlock()
	}
	return saved, err
}
func (s *Service) DraftFrom(ctx context.Context, expected, revision string) (model.ConfigRevision, error) {
	if err := s.enter(ctx); err != nil {
		return model.ConfigRevision{}, err
	}
	defer func() { <-s.gate }()
	if err := s.writable(); err != nil {
		return model.ConfigRevision{}, err
	}
	repo, err := s.management()
	if err != nil {
		return model.ConfigRevision{}, err
	}
	old, err := repo.Revision(ctx, revision)
	if err != nil {
		return model.ConfigRevision{}, err
	}
	input, err := s.ValidateDraft(ctx, model.DraftInput{Config: old.Config, CredentialAssets: old.CredentialAssets, CertificateAssets: old.CertificateAssets})
	if err != nil {
		return model.ConfigRevision{}, err
	}
	saved, err := repo.SaveDraftReferences(ctx, expected, input)
	if err == nil {
		s.mu.Lock()
		s.knownHeads.DraftRevision = saved.ID
		clear(s.plans)
		s.mu.Unlock()
	}
	return saved, err
}
func (s *Service) MutateAsset(ctx context.Context, action func(context.Context, ports.ManagementRepository) error) error {
	if err := s.enter(ctx); err != nil {
		return err
	}
	defer func() { <-s.gate }()
	if err := s.writable(); err != nil {
		return err
	}
	repo, err := s.management()
	if err != nil {
		return err
	}
	work, cancel := s.workContext(ctx)
	defer cancel()
	return action(work, repo)
}
func (s *Service) CreatePlan(ctx context.Context, draft, base string) (ApplicationPlan, error) {
	if err := s.enter(ctx); err != nil {
		return ApplicationPlan{}, err
	}
	defer func() { <-s.gate }()
	if err := s.writable(); err != nil {
		return ApplicationPlan{}, err
	}
	heads, err := s.repository.Heads(ctx)
	if err != nil {
		return ApplicationPlan{}, err
	}
	if heads.DraftRevision != draft || heads.CommittedRevision != base {
		return ApplicationPlan{}, ports.ErrConflict
	}
	snapshot, err := s.repository.Resolve(ctx, draft)
	if err != nil {
		return ApplicationPlan{}, err
	}
	snapshot, err = s.normalize(snapshot)
	if err != nil {
		return ApplicationPlan{}, err
	}
	preview, err := s.runtime.Plan(snapshot)
	if err != nil {
		return ApplicationPlan{}, err
	}
	plan := ApplicationPlan{ID: "plan_" + rand.Text(), DraftRevision: draft, BaseRevision: base, BootID: s.runtime.Snapshot().BootID, RuntimeEpoch: preview.RuntimeEpoch, ExpiresAt: time.Now().UTC().Add(planTTL), Changes: slices.Clone(preview.Changes)}
	committed, err := s.repository.Revision(ctx, base)
	if err != nil {
		return ApplicationPlan{}, err
	}
	expected := map[string]bool{}
	for _, spec := range committed.Config.Listeners {
		expected[spec.ID] = spec.Enabled
	}
	for i := range plan.Changes {
		if plan.Changes[i].Action == "create" && expected[plan.Changes[i].ID] {
			plan.Changes[i].Action = "recover"
		}
		if plan.Changes[i].Action == "keep" {
			plan.Changes[i].Action = "unchanged"
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, value := range s.plans {
		if !value.ExpiresAt.After(time.Now()) {
			delete(s.plans, id)
		}
	}
	if len(s.plans) >= maxPlans {
		return ApplicationPlan{}, ports.ErrBusy
	}
	stored := plan
	stored.Changes = slices.Clone(plan.Changes)
	s.plans[plan.ID] = stored
	return plan, nil
}
func ManagementRequestDigest(planID string, acknowledged bool) string {
	raw, _ := json.Marshal(struct {
		Plan         string
		Acknowledged bool
	}{planID, acknowledged})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// AcceptPlan commits admission before returning. The worker is owned by Service,
// never by a Hertz context, HTTP connection, administrator session or logout.
func (s *Service) AcceptPlan(ctx context.Context, key, planID string, acknowledged bool) (model.ApplyOperation, error) {
	digest := ManagementRequestDigest(planID, acknowledged)
	prior, err := s.repository.Operation(ctx, key)
	if err == nil {
		if prior.CallerDigest != digest {
			return prior, ports.ErrIdempotencyConflict
		}
		return s.operationView(prior), nil
	}
	if !errors.Is(err, ports.ErrNotFound) {
		return model.ApplyOperation{}, err
	}
	if err = s.enter(ctx); err != nil {
		// A concurrent identical admission may have just acquired the gate.
		if errors.Is(err, ports.ErrBusy) {
			prior, e := s.repository.Operation(ctx, key)
			if e == nil {
				if prior.CallerDigest != digest {
					return prior, ports.ErrIdempotencyConflict
				}
				return s.operationView(prior), nil
			}
		}
		return model.ApplyOperation{}, err
	}
	owned := true
	defer func() {
		if owned {
			<-s.gate
		}
	}()
	if err = s.writable(); err != nil {
		return model.ApplyOperation{}, err
	}
	s.mu.RLock()
	plan, found := s.plans[planID]
	s.mu.RUnlock()
	status := s.runtime.Snapshot()
	if !found || !plan.ExpiresAt.After(time.Now()) || plan.BootID != status.BootID || plan.RuntimeEpoch != status.RuntimeEpoch {
		return model.ApplyOperation{}, ErrPlanExpired
	}
	for _, change := range plan.Changes {
		if change.ClosesConnections && !acknowledged {
			return model.ApplyOperation{}, ErrDisconnectAcknowledgement
		}
	}
	work, cancel := context.WithTimeout(s.ctx, persistenceTimeout)
	defer cancel()
	heads, err := s.repository.Heads(work)
	if err != nil {
		return model.ApplyOperation{}, err
	}
	if heads.DraftRevision != plan.DraftRevision || heads.CommittedRevision != plan.BaseRevision {
		return model.ApplyOperation{}, ErrPlanExpired
	}
	snapshot, err := s.repository.Resolve(work, plan.DraftRevision)
	if err != nil {
		return model.ApplyOperation{}, err
	}
	snapshot, err = s.normalize(snapshot)
	if err != nil {
		return model.ApplyOperation{}, err
	}
	repo, err := s.management()
	if err != nil {
		return model.ApplyOperation{}, err
	}
	op, replayed, err := repo.BeginManagedApply(work, key, plan.DraftRevision, plan.BaseRevision, digest)
	if err != nil {
		if errors.Is(err, ports.ErrBusy) || errors.Is(err, ports.ErrConflict) || errors.Is(err, ports.ErrIdempotencyConflict) {
			return op, err
		}
		check, stop := context.WithTimeout(context.Background(), persistenceTimeout)
		defer stop()
		observed, checkErr := repo.Operation(check, key)
		if errors.Is(checkErr, ports.ErrNotFound) {
			return op, err
		}
		if checkErr != nil {
			s.block("operation admission outcome is unknown")
			op.Status = "uncertain"
			op.Error = "operation admission outcome is unknown"
			s.rememberUncertain(op)
			return op, ErrPersistenceUncertain
		}
		if observed.CallerDigest != digest {
			return observed, ports.ErrIdempotencyConflict
		}
		op = observed
		if op.Terminal() {
			return op, nil
		}
	} else if replayed {
		return op, nil
	}
	s.mu.Lock()
	s.applying = true
	s.activeOperation = op.ID
	delete(s.plans, planID)
	s.mu.Unlock()
	owned = false
	go func() {
		defer func() { <-s.gate }()
		job, stop := context.WithTimeout(s.ctx, applyTimeout)
		defer stop()
		_, _ = s.runAccepted(job, op, snapshot, &plan.RuntimeEpoch)
	}()
	return op, nil
}

// CommittedListener provides a consistent, private snapshot for the sensitive
// connection-information action. The caller must authorize it before entry.
func (s *Service) CommittedListener(ctx context.Context, expected, id string) (*model.RuntimeConfig, model.ListenerSpec, string, error) {
	if err := s.enter(ctx); err != nil {
		return nil, model.ListenerSpec{}, "", err
	}
	defer func() { <-s.gate }()
	status, err := s.Status(ctx)
	if err != nil {
		return nil, model.ListenerSpec{}, "", err
	}
	if status.Provisional || status.Applying || status.WritesBlocked || status.Heads.CommittedRevision != expected {
		return nil, model.ListenerSpec{}, "", ports.ErrConflict
	}
	snapshot, err := s.repository.Resolve(ctx, expected)
	if err != nil {
		return nil, model.ListenerSpec{}, "", err
	}
	preview, err := s.runtime.Plan(snapshot)
	if err != nil {
		return nil, model.ListenerSpec{}, "", err
	}
	for _, change := range preview.Changes {
		if change.ID == id && change.Action != "keep" {
			return nil, model.ListenerSpec{}, "", ports.ErrConflict
		}
	}
	for _, spec := range snapshot.Config.Listeners {
		if spec.ID == id {
			for _, actual := range status.Runtime.Listeners {
				if actual.ID == id && actual.State == "running" && !actual.Provisional {
					return snapshot, spec, actual.SpecDigest, nil
				}
			}
			return nil, model.ListenerSpec{}, "", ports.ErrConflict
		}
	}
	return nil, model.ListenerSpec{}, "", ports.ErrNotFound
}

func (s *Service) rememberUncertain(op model.ApplyOperation) {
	if op.ID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	copy := op
	s.uncertain = &copy
	s.activeOperation = op.ID
}
func (s *Service) operationView(op model.ApplyOperation) model.ApplyOperation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.uncertain != nil && s.uncertain.ID == op.ID {
		return *s.uncertain
	}
	return op
}
func (s *Service) Operation(ctx context.Context, id string) (model.ApplyOperation, error) {
	s.mu.RLock()
	if s.uncertain != nil && s.uncertain.ID == id {
		copy := *s.uncertain
		s.mu.RUnlock()
		return copy, nil
	}
	s.mu.RUnlock()
	repo, err := s.management()
	if err != nil {
		return model.ApplyOperation{}, err
	}
	return repo.OperationID(ctx, id)
}
