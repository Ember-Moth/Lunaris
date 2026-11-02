// SPDX-License-Identifier: GPL-3.0-only
package node

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/inbound"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/Ember-Moth/Lunaris/internal/transport"
)

type scriptedFactory struct {
	mu         sync.Mutex
	counts     map[string]int
	instances  []*scriptedInstance
	afterBuild func(model.ListenerSpec, int)
	start      func(context.Context, model.ListenerSpec, int) error
	stop       func(context.Context, model.ListenerSpec, int) error
}

type scriptedInstance struct {
	factory *scriptedFactory
	spec    model.ListenerSpec
	number  int
	events  chan protocol.InstanceEvent
	closed  atomic.Bool
}

func (*scriptedFactory) Capabilities() protocol.Capabilities {
	return protocol.Capabilities{Type: "scripted", TCP: true, Transports: []string{"scripted"}}
}
func (*scriptedFactory) Validate(model.ListenerSpec) []model.FieldError { return nil }
func (f *scriptedFactory) Build(spec protocol.ResolvedListenerSpec, _ protocol.Dependencies) (transport.Binding, error) {
	f.mu.Lock()
	if f.counts == nil {
		f.counts = make(map[string]int)
	}
	f.counts[spec.Spec.ID]++
	instance := &scriptedInstance{factory: f, spec: spec.Spec, number: f.counts[spec.Spec.ID], events: make(chan protocol.InstanceEvent, 8)}
	f.instances = append(f.instances, instance)
	f.mu.Unlock()
	if f.afterBuild != nil {
		f.afterBuild(instance.spec, instance.number)
	}
	return transport.Binding{}, nil
}
func (f *scriptedFactory) last(id string) *scriptedInstance {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.instances) - 1; i >= 0; i-- {
		if f.instances[i].spec.ID == id {
			return f.instances[i]
		}
	}
	return nil
}
func (i *scriptedInstance) Start(ctx context.Context) error {
	if i.factory.start != nil {
		if err := i.factory.start(ctx, i.spec, i.number); err != nil {
			return err
		}
	}
	i.events <- protocol.InstanceEvent{State: "running"}
	return nil
}
func (i *scriptedInstance) Events() <-chan protocol.InstanceEvent { return i.events }
func (i *scriptedInstance) Stop(ctx context.Context) error {
	if i.factory.stop != nil {
		if err := i.factory.stop(ctx, i.spec, i.number); err != nil {
			return err
		}
	}
	if i.closed.CompareAndSwap(false, true) {
		i.events <- protocol.InstanceEvent{State: "stopped"}
	}
	return nil
}

func fakeConfig() *model.RuntimeConfig {
	return &model.RuntimeConfig{Config: model.NodeConfig{SchemaVersion: 1, Limits: model.DefaultLimits(), Listeners: []model.ListenerSpec{
		{ID: "a", Enabled: true, Protocol: "scripted", Address: "127.0.0.1", Port: 17001, Network: []string{"tcp"}, Options: json.RawMessage(`{"version":1}`)},
		{ID: "b", Enabled: true, Protocol: "scripted", Address: "127.0.0.1", Port: 17002, Network: []string{"tcp"}, Options: json.RawMessage(`{"version":1}`)},
	}}, Credentials: map[string][]byte{}}
}

func startFake(t *testing.T, f *scriptedFactory) *Runtime {
	t.Helper()
	p, _ := protocol.NewRegistry(f)
	tr, _ := transport.NewRegistry(scriptedTransport{factory: f})
	registry, _ := inbound.NewRegistry(p, tr)
	runtime, err := Start(context.Background(), fakeConfig(), registry, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := runtime.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return runtime
}

func TestStatusResponsiveAndConcurrentApplyRejected(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	factory := &scriptedFactory{start: func(ctx context.Context, spec model.ListenerSpec, n int) error {
		if spec.ID == "a" && n == 2 {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}}
	runtime := startFake(t, factory)
	old := factory.last("a")
	changed := fakeConfig()
	changed.Config.Listeners[0].Options = json.RawMessage(`{"version":2}`)
	done := make(chan error, 1)
	go func() { _, err := runtime.Apply(context.Background(), changed); done <- err }()
	<-entered
	observed := make(chan Status, 1)
	go func() { observed <- runtime.Snapshot() }()
	select {
	case status := <-observed:
		if !status.Applying {
			t.Fatal("application state missing")
		}
	case <-time.After(time.Second):
		t.Fatal("status blocked behind network initialization")
	}
	if _, err := runtime.Apply(context.Background(), changed); !errors.Is(err, ErrBusy) {
		t.Fatalf("concurrent apply was not rejected: %v", err)
	}
	if _, err := runtime.Plan(changed); !errors.Is(err, ErrBusy) {
		t.Fatalf("plan exposed transition state: %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	old.events <- protocol.InstanceEvent{State: "failed", Err: errors.New("stale generation failure")}
	if status := listenerStatus(t, runtime, "a"); status.State != "running" || status.Generation == 1 {
		t.Fatalf("late event affected new generation: %+v", status)
	}
	select {
	case err := <-runtime.Errors():
		t.Fatalf("retired generation emitted failure: %v", err)
	default:
	}
}

func TestFailedRollbackIsVisibleAndCanBeRecovered(t *testing.T) {
	factory := &scriptedFactory{start: func(_ context.Context, spec model.ListenerSpec, n int) error {
		if spec.ID == "a" && (n == 2 || n == 3) {
			return errors.New("injected bind failure")
		}
		return nil
	}}
	runtime := startFake(t, factory)
	beforeB := listenerStatus(t, runtime, "b")
	changed := fakeConfig()
	changed.Config.Listeners[0].Options = json.RawMessage(`{"version":2}`)
	result, err := runtime.Apply(context.Background(), changed)
	if err == nil || result.Outcome != "degraded" {
		t.Fatalf("rollback failure hidden: %+v %v", result, err)
	}
	status := runtime.Snapshot()
	if !status.Degraded || status.RecoveryRequired || status.Revision != 1 {
		t.Fatalf("incorrect failure status: %+v", status)
	}
	result, err = runtime.Apply(context.Background(), fakeConfig())
	if err != nil {
		t.Fatal(err)
	}
	if result.Revision != 1 || runtime.Snapshot().Degraded {
		t.Fatal("recovery did not restore unchanged config")
	}
	if listenerStatus(t, runtime, "b").Generation != beforeB.Generation {
		t.Fatal("recovery restarted an unaffected listener")
	}
}

func TestUnconfirmedResourceReleaseBlocksFurtherApplication(t *testing.T) {
	var allowStop atomic.Bool
	factory := &scriptedFactory{stop: func(_ context.Context, spec model.ListenerSpec, _ int) error {
		if spec.ID == "a" && !allowStop.Load() {
			return errors.New("resource did not close")
		}
		return nil
	}}
	runtime := startFake(t, factory)
	defer allowStop.Store(true)
	changed := fakeConfig()
	changed.Config.Listeners[0].Options = json.RawMessage(`{"version":2}`)
	result, err := runtime.Apply(context.Background(), changed)
	if err == nil || result.Outcome != "degraded" {
		t.Fatalf("unconfirmed resource release was hidden: %+v %v", result, err)
	}
	status := runtime.Snapshot()
	if !status.RecoveryRequired || !status.Degraded || status.Revision != 1 {
		t.Fatalf("incorrect retained-resource status: %+v", status)
	}
	if _, err := runtime.Apply(context.Background(), fakeConfig()); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("applied over an unreleased resource: %v", err)
	}
}

func TestShutdownDuringApplyDoesNotResurrectBaseline(t *testing.T) {
	entered := make(chan struct{})
	factory := &scriptedFactory{start: func(ctx context.Context, spec model.ListenerSpec, n int) error {
		if spec.ID == "a" && n == 2 {
			close(entered)
			<-ctx.Done()
			return ctx.Err()
		}
		return nil
	}}
	runtime := startFake(t, factory)
	changed := fakeConfig()
	changed.Config.Listeners[0].Options = json.RawMessage(`{"version":2}`)
	done := make(chan ApplyResult, 1)
	go func() { result, _ := runtime.Apply(context.Background(), changed); done <- result }()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := runtime.Close(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-done:
		if result.Outcome != "interrupted" {
			t.Fatalf("unexpected shutdown result: %+v", result)
		}
	case <-ctx.Done():
		t.Fatal("apply did not stop")
	}
	if factory.last("a").number != 2 {
		t.Fatal("shutdown recreated the old listener")
	}
	if !runtime.Snapshot().Closed {
		t.Fatal("runtime did not close")
	}
}

func TestCanceledApplyRestoresBaselineWithoutCancelingRuntime(t *testing.T) {
	entered := make(chan struct{})
	factory := &scriptedFactory{start: func(ctx context.Context, spec model.ListenerSpec, n int) error {
		if spec.ID == "a" && n == 2 {
			close(entered)
			<-ctx.Done()
			return ctx.Err()
		}
		return nil
	}}
	runtime := startFake(t, factory)
	changed := fakeConfig()
	changed.Config.Listeners[0].Options = json.RawMessage(`{"version":2}`)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type response struct {
		result ApplyResult
		err    error
	}
	done := make(chan response, 1)
	go func() { result, err := runtime.Apply(ctx, changed); done <- response{result, err} }()
	<-entered
	cancel()
	select {
	case response := <-done:
		if response.result.Outcome != "rolled_back" || !errors.Is(response.err, context.Canceled) {
			t.Fatalf("incorrect cancellation result: %+v %v", response.result, response.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled application did not recover")
	}
	status := runtime.Snapshot()
	if status.Closed || status.Degraded || status.Revision != 1 {
		t.Fatalf("cancellation destroyed baseline: %+v", status)
	}
}

// The fake carrier exposes lifecycle failures without opening real sockets.
// Runtime composition builds the protocol and carrier consecutively.
type scriptedTransport struct{ factory *scriptedFactory }

func (scriptedTransport) Capabilities() transport.Capabilities {
	return transport.Capabilities{Type: "scripted", TCP: true}
}
func (scriptedTransport) Validate(model.ListenerSpec) []model.FieldError { return nil }
func (t scriptedTransport) Build(r transport.ResolvedSpec, _ transport.Binding) (transport.Instance, error) {
	t.factory.mu.Lock()
	defer t.factory.mu.Unlock()
	i := t.factory.instances[len(t.factory.instances)-1]
	if i.spec.Port != r.Port {
		return nil, errors.New("scripted transport construction mismatch")
	}
	return i, nil
}

func TestExpectedEpochRejectsPreviewAfterRuntimeChanges(t *testing.T) {
	factory := &scriptedFactory{}
	runtime := startFake(t, factory)
	plan, err := runtime.Plan(fakeConfig())
	if err != nil {
		t.Fatal(err)
	}
	runtime.mu.Lock()
	runtime.epoch++
	runtime.mu.Unlock()
	result, err := runtime.ApplyExpected(context.Background(), fakeConfig(), &plan.RuntimeEpoch)
	if !errors.Is(err, ErrStalePlan) || result.Outcome != "rejected" {
		t.Fatal(result, err)
	}
	for _, instance := range factory.instances {
		if instance.closed.Load() {
			t.Fatal("stale plan closed a live instance")
		}
	}
}

func TestStalePreviewDuringBuildRetainsFailedCandidateCleanup(t *testing.T) {
	for _, failCleanup := range []bool{false, true} {
		name := "released"
		if failCleanup {
			name = "retained"
		}
		t.Run(name, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			var allowStop atomic.Bool
			factory := &scriptedFactory{
				afterBuild: func(spec model.ListenerSpec, n int) {
					if spec.ID == "a" && n == 2 {
						close(entered)
						<-release
					}
				},
				stop: func(_ context.Context, spec model.ListenerSpec, n int) error {
					if failCleanup && spec.ID == "a" && n == 2 && !allowStop.Load() {
						return errors.New("candidate resources remain owned")
					}
					return nil
				},
			}
			runtime := startFake(t, factory)
			t.Cleanup(func() {
				allowStop.Store(true)
				releaseOnce.Do(func() { close(release) })
			})
			oldA := factory.last("a")
			beforeA := listenerStatus(t, runtime, "a")
			changed := fakeConfig()
			changed.Config.Listeners[0].Options = json.RawMessage(`{"version":2}`)
			plan, err := runtime.Plan(changed)
			if err != nil {
				t.Fatal(err)
			}
			type response struct {
				result ApplyResult
				err    error
			}
			done := make(chan response, 1)
			go func() {
				result, err := runtime.ApplyExpected(context.Background(), changed, &plan.RuntimeEpoch)
				done <- response{result, err}
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("candidate build did not begin")
			}
			factory.last("b").events <- protocol.InstanceEvent{State: "failed", Err: errors.New("listener failed during preparation")}
			select {
			case <-runtime.Errors():
			case <-time.After(time.Second):
				t.Fatal("runtime did not observe baseline failure")
			}
			releaseOnce.Do(func() { close(release) })
			var applied response
			select {
			case applied = <-done:
			case <-time.After(time.Second):
				t.Fatal("stale apply did not finish")
			}
			outcome := "rejected"
			if failCleanup {
				outcome = "degraded"
			}
			if !errors.Is(applied.err, ErrStalePlan) || applied.result.Outcome != outcome {
				t.Fatalf("incorrect stale apply result: %+v %v", applied.result, applied.err)
			}
			status := runtime.Snapshot()
			if oldA.closed.Load() || status.Revision != 1 || listenerStatus(t, runtime, "a").Generation != beforeA.Generation {
				t.Fatal("stale preview replaced the healthy baseline")
			}
			if status.RecoveryRequired != failCleanup || (len(status.RetainedInstances) > 0) != failCleanup {
				t.Fatalf("candidate ownership was lost: %+v", status)
			}
			if failCleanup {
				if _, err := runtime.Apply(context.Background(), changed); !errors.Is(err, ErrRecoveryRequired) {
					t.Fatalf("replacement admitted over retained candidate: %v", err)
				}
			} else if !factory.last("a").closed.Load() {
				t.Fatal("rejected candidate was not released")
			}
		})
	}
}
