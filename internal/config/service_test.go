// SPDX-License-Identifier: GPL-3.0-only
package config

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol/builtin"
	ports "github.com/Ember-Moth/Lunaris/internal/store"
	"github.com/Ember-Moth/Lunaris/internal/store/sqlite"
)

func serviceConfig(secret string) *model.RuntimeConfig {
	return &model.RuntimeConfig{Config: model.NodeConfig{SchemaVersion: 1, Limits: model.DefaultLimits(), Listeners: []model.ListenerSpec{}}, Credentials: map[string][]byte{"key": []byte(secret)}}
}

func closeService(t *testing.T, service *Service) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := service.Close(ctx); err != nil {
		t.Error(err)
	}
}

func TestServiceCommitsAndRestartsOnlyCommittedRevision(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	repository, err := sqlite.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	registry, _ := builtin.NewRegistry()
	service, err := OpenService(ctx, repository, registry, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenService(ctx, repository, registry, false); err == nil {
		t.Fatal("two services claimed the same store")
	}
	first, err := service.SaveDraft(ctx, "r0", serviceConfig("durable-old-secret"))
	if err != nil {
		t.Fatal(err)
	}
	op, err := service.Apply(ctx, "first-key", first.ID, "")
	if err != nil || op.Status != "succeeded" {
		t.Fatal(err)
	}
	before, _ := service.Status(ctx)
	duplicate, err := service.Apply(ctx, "first-key", first.ID, "")
	if err != nil || duplicate.ID != op.ID {
		t.Fatal("retry was not idempotent", err)
	}
	after, _ := service.Status(ctx)
	if after.Runtime.Revision != before.Runtime.Revision {
		t.Fatal("duplicate operation re-applied runtime")
	}
	second, err := service.SaveDraft(ctx, first.ID, serviceConfig("uncommitted-new-secret"))
	if err != nil {
		t.Fatal(err)
	}
	closeService(t, service)
	if err := repository.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := sqlite.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	managed, err := OpenService(ctx, reopened, registry, true)
	if err != nil {
		t.Fatal(err)
	}
	defer closeService(t, managed)
	state, err := managed.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.RuntimeRevision != first.ID || state.Heads.DraftRevision != second.ID {
		t.Fatalf("draft activated on restart: %+v", state)
	}
	resolved, err := reopened.Resolve(ctx, state.RuntimeRevision)
	if err != nil || string(resolved.Credentials["key"]) != "durable-old-secret" {
		t.Fatal("committed secret was not restored", err)
	}
	encoded, _ := json.Marshal(state)
	if bytes.Contains(encoded, []byte("durable-old-secret")) {
		t.Fatal("status exposed a secret")
	}
	if _, err := managed.Apply(ctx, "second-key", second.ID, first.ID); err != nil {
		t.Fatal(err)
	}
	current, _ := managed.Status(ctx)
	if _, err := managed.Apply(ctx, "first-key", first.ID, ""); err != nil {
		t.Fatal("historic retry was rejected", err)
	}
	still, _ := managed.Status(ctx)
	if still.RuntimeRevision != second.ID || still.Runtime.Revision != current.Runtime.Revision {
		t.Fatal("historic retry reverted active config")
	}
}

type commitFault struct {
	*sqlite.Store
	mode        string
	readsFailed atomic.Bool
}

func (f *commitFault) CommitApply(ctx context.Context, id string) (model.ApplyOperation, error) {
	var operation model.ApplyOperation
	var err error
	if f.mode == "after" || f.mode == "unknown-after" {
		operation, err = f.Store.CommitApply(ctx, id)
		if err != nil {
			return operation, err
		}
	}
	if f.mode == "unknown-before" || f.mode == "unknown-after" {
		f.readsFailed.Store(true)
	}
	return operation, errors.New("injected commit response failure")
}
func (f *commitFault) Operation(ctx context.Context, key string) (model.ApplyOperation, error) {
	if f.readsFailed.Load() {
		return model.ApplyOperation{}, errors.New("injected read outage")
	}
	return f.Store.Operation(ctx, key)
}
func (f *commitFault) Heads(ctx context.Context) (model.ConfigHeads, error) {
	if f.readsFailed.Load() {
		return model.ConfigHeads{}, errors.New("injected read outage")
	}
	return f.Store.Heads(ctx)
}

func TestCommitFailuresAreResolvedWithoutGuessing(t *testing.T) {
	for _, mode := range []string{"before", "after", "unknown-before", "unknown-after"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			repository, err := sqlite.Open(ctx, dir)
			if err != nil {
				t.Fatal(err)
			}
			fault := &commitFault{Store: repository, mode: mode}
			registry, _ := builtin.NewRegistry()
			service, err := OpenService(ctx, fault, registry, false)
			if err != nil {
				t.Fatal(err)
			}
			draft, err := service.SaveDraft(ctx, "r0", serviceConfig("fault-test-secret"))
			if err != nil {
				t.Fatal(err)
			}
			op, applyErr := service.Apply(ctx, "fault-key", draft.ID, "")
			state, _ := service.Status(ctx)
			switch mode {
			case "before":
				if applyErr == nil || op.Status != "failed_rolled_back" || state.Heads.CommittedRevision != "r0" || state.RuntimeRevision != "" || state.WritesBlocked {
					t.Fatalf("known failure not compensated: %+v %+v %v", op, state, applyErr)
				}
			case "after":
				if applyErr != nil || op.Status != "succeeded" || state.RuntimeRevision != draft.ID || state.Provisional {
					t.Fatalf("committed response was guessed backward: %+v %+v %v", op, state, applyErr)
				}
			default:
				if !errors.Is(applyErr, ErrPersistenceUncertain) || op.Terminal() || !state.WritesBlocked || state.HeadsKnown || state.RuntimeRevision != draft.ID {
					t.Fatalf("uncertainty was hidden: %+v %+v %v", op, state, applyErr)
				}
				if _, err := service.SaveDraft(ctx, draft.ID, serviceConfig("blocked-write")); !errors.Is(err, ErrPersistenceUncertain) {
					t.Fatal("write accepted during uncertainty")
				}
			}
			closeService(t, service)
			repository.Close()
			reopened, err := sqlite.Open(ctx, dir)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			restored, err := OpenService(ctx, reopened, registry, true)
			if err != nil {
				t.Fatal(err)
			}
			defer closeService(t, restored)
			state, err = restored.Status(ctx)
			if err != nil {
				t.Fatal(err)
			}
			expected := "r0"
			if mode == "after" || mode == "unknown-after" {
				expected = draft.ID
			}
			if state.RuntimeRevision != expected || state.WritesBlocked {
				t.Fatalf("restart restored wrong revision: %+v", state)
			}
			before := state.Runtime.Revision
			replayed, err := restored.Apply(ctx, "fault-key", draft.ID, "")
			if expected == "r0" && err == nil {
				t.Fatal("failed/interrupted request re-executed")
			}
			if expected == draft.ID && (err != nil || replayed.Status != "succeeded") {
				t.Fatal("committed request result lost", err)
			}
			state, _ = restored.Status(ctx)
			if state.Runtime.Revision != before {
				t.Fatal("retry changed runtime")
			}
		})
	}
}

func TestOfflineApplyCanRepairAnUnavailableCommittedBinding(t *testing.T) {
	ctx := context.Background()
	repository, err := sqlite.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	input := serviceConfig("repair-secret")
	input.Config.Listeners = []model.ListenerSpec{{ID: "ss", Enabled: true, Protocol: "shadowsocks", Address: "127.0.0.1", Port: uint16(occupied.Addr().(*net.TCPAddr).Port), Network: []string{"tcp"}, CredentialRefs: []string{"key"}, Options: json.RawMessage(`{"method":"aes-128-gcm"}`)}}
	old, err := repository.SaveDraft(ctx, "r0", input)
	if err != nil {
		t.Fatal(err)
	}
	op, _, err := repository.BeginApply(ctx, "fixture", old.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CommitApply(ctx, op.ID); err != nil {
		t.Fatal(err)
	}
	registry, _ := builtin.NewRegistry()
	if started, err := OpenService(ctx, repository, registry, true); err == nil {
		closeService(t, started)
		t.Fatal("unavailable committed binding reported ready")
	}
	offline, err := OpenService(ctx, repository, registry, false)
	if err != nil {
		t.Fatal(err)
	}
	defer closeService(t, offline)
	repair, err := offline.SaveDraft(ctx, old.ID, serviceConfig("repair-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := offline.Apply(ctx, "repair", repair.ID, old.ID); err != nil {
		t.Fatal(err)
	}
	heads, _ := repository.Heads(ctx)
	if heads.CommittedRevision != repair.ID {
		t.Fatal("offline repair was not committed")
	}
	if _, err := offline.Apply(ctx, "repair", old.ID, old.ID); !errors.Is(err, ports.ErrIdempotencyConflict) {
		t.Fatal("repair request key reused")
	}
}

func TestNetworkFailureNeverAdvancesCommittedHead(t *testing.T) {
	ctx := context.Background()
	repository, err := sqlite.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	registry, _ := builtin.NewRegistry()
	service, err := OpenService(ctx, repository, registry, false)
	if err != nil {
		t.Fatal(err)
	}
	defer closeService(t, service)
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	input := serviceConfig("network-failure-secret")
	input.Config.Listeners = []model.ListenerSpec{{ID: "ss", Enabled: true, Protocol: "shadowsocks", Address: "127.0.0.1", Port: uint16(occupied.Addr().(*net.TCPAddr).Port), Network: []string{"tcp"}, CredentialRefs: []string{"key"}, Options: json.RawMessage(`{"method":"aes-128-gcm"}`)}}
	draft, err := service.SaveDraft(ctx, "r0", input)
	if err != nil {
		t.Fatal(err)
	}
	op, err := service.Apply(ctx, "binding-failed", draft.ID, "")
	if err == nil || op.Status != "failed_rolled_back" {
		t.Fatalf("failed bind was committed: %+v %v", op, err)
	}
	heads, _ := repository.Heads(ctx)
	if heads.CommittedRevision != "r0" || heads.DraftRevision != draft.ID {
		t.Fatalf("failure corrupted heads: %+v", heads)
	}
	occupied.Close()
	if _, err := service.Apply(ctx, "binding-failed", draft.ID, ""); !errors.Is(err, ErrStoredOperationFailed) {
		t.Fatal("failed request was retried under the same key")
	}
	if _, err := service.Apply(ctx, "binding-retry", draft.ID, ""); err != nil {
		t.Fatal(err)
	}
}

type admissionFault struct{ *sqlite.Store }

func (f *admissionFault) BeginApply(ctx context.Context, key, target, base string) (model.ApplyOperation, bool, error) {
	op, replayed, err := f.Store.BeginApply(ctx, key, target, base)
	if err != nil {
		return op, replayed, err
	}
	return op, replayed, errors.New("lost admission response")
}

func TestLostAdmissionResponseDoesNotApplyRuntime(t *testing.T) {
	ctx := context.Background()
	repository, err := sqlite.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	registry, _ := builtin.NewRegistry()
	service, err := OpenService(ctx, &admissionFault{repository}, registry, false)
	if err != nil {
		t.Fatal(err)
	}
	defer closeService(t, service)
	draft, err := service.SaveDraft(ctx, "r0", serviceConfig("admission-secret"))
	if err != nil {
		t.Fatal(err)
	}
	before, _ := service.Status(ctx)
	op, err := service.Apply(ctx, "lost-admission", draft.ID, "")
	if err == nil || op.Status != "interrupted" {
		t.Fatalf("admission failure not finalized: %+v %v", op, err)
	}
	after, _ := service.Status(ctx)
	if after.Runtime.Revision != before.Runtime.Revision || after.Heads.CommittedRevision != "r0" || after.WritesBlocked {
		t.Fatalf("admission failure changed runtime: %+v", after)
	}
}
