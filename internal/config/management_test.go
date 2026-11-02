// SPDX-License-Identifier: GPL-3.0-only
package config

import (
	"context"
	"errors"
	"fmt"
	"github.com/Ember-Moth/Lunaris/internal/inbound"
	"github.com/Ember-Moth/Lunaris/internal/node"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/Ember-Moth/Lunaris/internal/transport"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol/builtin"
	ports "github.com/Ember-Moth/Lunaris/internal/store"
	"github.com/Ember-Moth/Lunaris/internal/store/sqlite"
)

func managementFixture(t *testing.T) (*sqlite.Store, *Service) {
	t.Helper()
	repo, err := sqlite.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	registry, _ := builtin.NewRegistry()
	s, err := OpenManagementService(context.Background(), repo, registry, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		closeService(t, s)
		if err := repo.Close(); err != nil {
			t.Error(err)
		}
	})
	return repo, s
}
func waitOperation(t *testing.T, repo ports.ManagementRepository, id string) model.ApplyOperation {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		op, err := repo.OperationID(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if op.Terminal() {
			return op
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("operation did not finish")
	return model.ApplyOperation{}
}
func TestPlanAdmissionOutlivesRequestAndReplaysAfterExpiry(t *testing.T) {
	repo, s := managementFixture(t)
	ctx := context.Background()
	credential, err := repo.CreateCredential(ctx, "password", "device", []byte("private-proxy-password"))
	if err != nil {
		t.Fatal(err)
	}
	input := model.DraftInput{Config: model.NodeConfig{SchemaVersion: 1, Limits: model.DefaultLimits(), Listeners: []model.ListenerSpec{}}, CredentialAssets: map[string]string{"device": credential.ID}}
	draft, err := s.SaveManagedDraft(ctx, "r0", input)
	if err != nil {
		t.Fatal(err)
	}
	if draft.CredentialAssets["device"] != credential.ID {
		t.Fatal("asset ID was copied instead of referenced")
	}
	plan, err := s.CreatePlan(ctx, draft.ID, "r0")
	if err != nil {
		t.Fatal(err)
	}
	request, cancel := context.WithCancel(ctx)
	op, err := s.AcceptPlan(request, "scoped-request", plan.ID, false)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	if result := waitOperation(t, repo, op.ID); result.Status != "succeeded" {
		t.Fatal(result)
	}
	// Plan removal and expiry never precede the persisted idempotency check.
	replay, err := s.AcceptPlan(ctx, "scoped-request", plan.ID, false)
	if err != nil || replay.ID != op.ID {
		t.Fatal(replay, err)
	}
	if _, err := s.AcceptPlan(ctx, "scoped-request", plan.ID, true); !errors.Is(err, ports.ErrIdempotencyConflict) {
		t.Fatal("changed request replay accepted", err)
	}
	if _, err := s.AcceptPlan(ctx, "new-request", plan.ID, false); !errors.Is(err, ErrPlanExpired) {
		t.Fatal("consumed plan reused", err)
	}
	if err := s.MutateAsset(ctx, func(ctx context.Context, r ports.ManagementRepository) error {
		return r.DeleteCredential(ctx, credential.ID)
	}); !errors.Is(err, ports.ErrReferenced) {
		t.Fatal("referenced credential deleted", err)
	}
}
func TestPlanStalenessAndManagementEndpoint(t *testing.T) {
	repo, s := managementFixture(t)
	ctx := context.Background()
	input := model.DraftInput{Config: model.NodeConfig{SchemaVersion: 1, Limits: model.DefaultLimits(), Listeners: []model.ListenerSpec{}}}
	plan, err := s.CreatePlan(ctx, "r0", "r0")
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	expired := s.plans[plan.ID]
	expired.ExpiresAt = time.Now().Add(-time.Second)
	s.plans[plan.ID] = expired
	s.mu.Unlock()
	if _, err := s.AcceptPlan(ctx, "expired-key", plan.ID, false); !errors.Is(err, ErrPlanExpired) {
		t.Fatal(err)
	}
	if _, err := s.SaveManagedDraft(ctx, "stale", input); !errors.Is(err, ports.ErrConflict) {
		t.Fatal(err)
	}
	asset, err := repo.CreateCredential(ctx, "password", "", []byte("a-test-secret"))
	if err != nil {
		t.Fatal(err)
	}
	s.reservedTCP = []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:9080")}
	input.CredentialAssets = map[string]string{"key": asset.ID}
	input.Config.Listeners = []model.ListenerSpec{{ID: "conflict", Enabled: true, Protocol: "shadowsocks", Address: "0.0.0.0", Port: 9080, Options: []byte(`{"method":"aes-128-gcm"}`), CredentialRefs: []string{"key"}}}
	if _, err := s.ValidateDraft(ctx, input); !errors.Is(err, ErrInvalidDraft) {
		t.Fatal("management endpoint overlap accepted", err)
	}
	input.Config.Listeners[0].Network = []string{"udp"}
	if _, err := s.ValidateDraft(ctx, input); err != nil {
		t.Fatal("UDP endpoint should not overlap TCP management", err)
	}
}
func TestManagementKeepsRepairAccessWhenCommittedPortIsBusy(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	repo, err := sqlite.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	registry, _ := builtin.NewRegistry()
	s, err := OpenService(ctx, repo, registry, false)
	if err != nil {
		t.Fatal(err)
	}
	temporary, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := temporary.Addr().String()
	port := uint16(temporary.Addr().(*net.TCPAddr).Port)
	temporary.Close()
	input := serviceConfig("restore-secret")
	input.Config.Listeners = []model.ListenerSpec{{ID: "ss", Enabled: true, Protocol: "shadowsocks", Address: "127.0.0.1", Port: port, Network: []string{"tcp"}, CredentialRefs: []string{"key"}, Options: []byte(`{"method":"aes-128-gcm"}`)}}
	draft, err := s.SaveDraft(ctx, "r0", input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Apply(ctx, "initial", draft.ID, "r0"); err != nil {
		t.Fatal(err)
	}
	closeService(t, s)
	occupied, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	managed, err := OpenManagementService(ctx, repo, registry, nil)
	if err != nil {
		t.Fatal("management repair entry was lost", err)
	}
	defer closeService(t, managed)
	state, err := managed.Status(ctx)
	if err != nil || state.RestoreError == "" || !state.Provisional {
		t.Fatal(state, err)
	}
	occupied.Close()
	plan, err := managed.CreatePlan(ctx, draft.ID, draft.ID)
	if err != nil {
		t.Fatal(err)
	}
	op, err := managed.AcceptPlan(ctx, "repair", plan.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if final := waitOperation(t, repo, op.ID); final.Status != "succeeded" {
		t.Fatal(final)
	}
	state, _ = managed.Status(ctx)
	if state.RestoreError != "" || state.Provisional {
		t.Fatal("repair did not converge", state)
	}
}

type managedBarrier struct {
	*sqlite.Store
	entered, release chan struct{}
	admissionFault   bool
}

func (r *managedBarrier) SetPhase(ctx context.Context, id, phase string) error {
	if phase == "applying" && r.entered != nil {
		close(r.entered)
		select {
		case <-r.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return r.Store.SetPhase(ctx, id, phase)
}
func (r *managedBarrier) BeginManagedApply(ctx context.Context, key, target, base, digest string) (model.ApplyOperation, bool, error) {
	op, replay, err := r.Store.BeginManagedApply(ctx, key, target, base, digest)
	if err == nil && r.admissionFault {
		return op, replay, context.Canceled
	}
	return op, replay, err
}
func TestAcceptedPlanOwnsLifetimeAndMutationGate(t *testing.T) {
	ctx := context.Background()
	repo, err := sqlite.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	barrier := &managedBarrier{Store: repo, entered: make(chan struct{}), release: make(chan struct{}), admissionFault: true}
	registry, _ := builtin.NewRegistry()
	s, err := OpenManagementService(ctx, barrier, registry, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeService(t, s)
	draft, err := s.SaveManagedDraft(ctx, "r0", model.DraftInput{Config: model.NodeConfig{SchemaVersion: 1, Limits: model.DefaultLimits(), Listeners: []model.ListenerSpec{}}})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := s.CreatePlan(ctx, draft.ID, "r0")
	if err != nil {
		t.Fatal(err)
	}
	request, cancel := context.WithCancel(ctx)
	op, err := s.AcceptPlan(request, "disconnect-after-admission", plan.ID, false)
	if err != nil {
		t.Fatal("durable admission was lost after its response failed", err)
	}
	<-barrier.entered
	cancel()
	state, err := s.Status(ctx)
	if err != nil || !state.Applying || state.ActiveOperation != op.ID {
		t.Fatal(state, err)
	}
	if err := s.MutateAsset(ctx, func(context.Context, ports.ManagementRepository) error {
		t.Error("mutation entered during apply")
		return nil
	}); !errors.Is(err, ports.ErrBusy) {
		t.Fatal(err)
	}
	replay, err := s.AcceptPlan(ctx, "disconnect-after-admission", plan.ID, false)
	if err != nil || replay.ID != op.ID {
		t.Fatal("in-progress replay failed", err)
	}
	close(barrier.release)
	if result := waitOperation(t, repo, op.ID); result.Status != "succeeded" {
		t.Fatal("HTTP cancellation cancelled accepted work", result)
	}
}
func TestManagedReplaySurvivesRestartWithoutPlan(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	repo, err := sqlite.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	registry, _ := builtin.NewRegistry()
	s, err := OpenManagementService(ctx, repo, registry, nil)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := s.CreatePlan(ctx, "r0", "r0")
	if err != nil {
		t.Fatal(err)
	}
	op, err := s.AcceptPlan(ctx, "durable-http-key", plan.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	waitOperation(t, repo, op.ID)
	closeService(t, s)
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := sqlite.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	restored, err := OpenManagementService(ctx, reopened, registry, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeService(t, restored)
	before, _ := restored.Status(ctx)
	replay, err := restored.AcceptPlan(ctx, "durable-http-key", plan.ID, false)
	if err != nil || replay.ID != op.ID {
		t.Fatal("replay required vanished plan", err)
	}
	after, _ := restored.Status(ctx)
	if after.Runtime.RuntimeEpoch != before.Runtime.RuntimeEpoch {
		t.Fatal("replay changed runtime")
	}
}

func TestUncertainManagedOperationRemainsVisible(t *testing.T) {
	ctx := context.Background()
	repo, err := sqlite.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	fault := &commitFault{Store: repo, mode: "unknown-after"}
	registry, _ := builtin.NewRegistry()
	s, err := OpenManagementService(ctx, fault, registry, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeService(t, s)
	plan, err := s.CreatePlan(ctx, "r0", "r0")
	if err != nil {
		t.Fatal(err)
	}
	op, err := s.AcceptPlan(ctx, "unknown-result", plan.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-s.OperationEvents():
		if event.Status != "uncertain" {
			t.Fatal(event)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("operation did not report uncertain state")
	}
	observed, err := s.Operation(ctx, op.ID)
	if err != nil || observed.Status != "uncertain" {
		t.Fatal("uncertain operation disappeared", observed, err)
	}
	state, _ := s.Status(ctx)
	if !state.WritesBlocked || state.ActiveOperation != op.ID {
		t.Fatal(state)
	}
}

type retainedFactory struct{ release chan struct{} }

func (retainedFactory) Capabilities() protocol.Capabilities {
	return protocol.Capabilities{Type: "retained", TCP: true, Transports: []string{"retained"}}
}
func (retainedFactory) Validate(model.ListenerSpec) []model.FieldError { return nil }
func (retainedFactory) Build(protocol.ResolvedListenerSpec, protocol.Dependencies) (transport.Binding, error) {
	return transport.Binding{Stream: &transport.StreamHandler{Serve: func(context.Context, net.Conn, M.Socksaddr, N.CloseHandlerFunc) error { return nil }}}, nil
}

type retainedTransport struct{ release chan struct{} }

func (retainedTransport) Capabilities() transport.Capabilities {
	return transport.Capabilities{Type: "retained", TCP: true}
}
func (retainedTransport) Validate(model.ListenerSpec) []model.FieldError { return nil }
func (f retainedTransport) Build(s transport.ResolvedSpec, _ transport.Binding) (transport.Instance, error) {
	return &retainedInstance{port: s.Port, release: f.release, events: make(chan transport.InstanceEvent, 4)}, nil
}

type retainedInstance struct {
	port    uint16
	release chan struct{}
	events  chan transport.InstanceEvent
	once    sync.Once
}

func (i *retainedInstance) Start(context.Context) error {
	if i.port == 2 {
		return errors.New("injected second listener failure")
	}
	i.events <- transport.InstanceEvent{State: "running"}
	return nil
}
func (i *retainedInstance) Events() <-chan transport.InstanceEvent { return i.events }
func (i *retainedInstance) Stop(ctx context.Context) error {
	if i.port == 1 {
		select {
		case <-i.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	i.once.Do(func() { i.events <- transport.InstanceEvent{State: "stopped"} })
	return nil
}
func TestManagementStartupRetainsUnreleasedRuntimeOwnership(t *testing.T) {
	ctx := context.Background()
	repo, err := sqlite.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	release := make(chan struct{})
	p, _ := protocol.NewRegistry(retainedFactory{release: release})
	tr, _ := transport.NewRegistry(retainedTransport{release: release})
	registry, _ := inbound.NewRegistry(p, tr)
	initial := serviceConfig("unused")
	initial.Config.Limits.ShutdownTimeout = 20 * time.Millisecond
	for _, port := range []uint16{1, 2} {
		initial.Config.Listeners = append(initial.Config.Listeners, model.ListenerSpec{ID: fmt.Sprint(port), Enabled: true, Protocol: "retained", Address: "127.0.0.1", Port: port, Network: []string{"tcp"}, Transport: model.Transport{Type: "retained"}, Options: []byte(`{}`)})
	}
	draft, err := repo.SaveDraft(ctx, "r0", initial)
	if err != nil {
		t.Fatal(err)
	}
	op, _, err := repo.BeginApply(ctx, "seed-committed", draft.ID, "r0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CommitApply(ctx, op.ID); err != nil {
		t.Fatal(err)
	}
	service, err := OpenManagementService(ctx, repo, registry, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { close(release); closeService(t, service) }()
	state, err := service.Status(ctx)
	if err != nil || !state.WritesBlocked || !state.Runtime.RecoveryRequired || len(state.Runtime.RetainedInstances)+len(state.Runtime.Listeners) == 0 {
		t.Fatal("failed startup resources were forgotten", state, err)
	}
	if _, err := service.CreatePlan(ctx, draft.ID, draft.ID); !errors.Is(err, node.ErrRecoveryRequired) {
		t.Fatal("replacement admitted over retained resources", err)
	}
}
