// SPDX-License-Identifier: GPL-3.0-only
package node

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/egress"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/Ember-Moth/Lunaris/internal/relay"
	"github.com/sagernet/sing/common/logger"
)

var (
	ErrBusy             = errors.New("configuration application is already in progress")
	ErrClosed           = errors.New("node runtime is closed")
	ErrRecoveryRequired = errors.New("unreleased runtime resources require a node restart")
)

type record struct {
	spec        model.ListenerSpec
	generation  uint64
	fingerprint string
	instance    protocol.Instance
	relay       *relay.Handler
	ctx         context.Context
	cancel      context.CancelFunc
	// All fields below are protected by Runtime.mu.
	state       string
	lastError   string
	retiring    bool
	provisional bool
}

// Runtime serializes configuration changes while status remains independently
// readable. Configurations and credentials retained here are owned snapshots.
type Runtime struct {
	ctx                             context.Context
	cancel                          context.CancelFunc
	registry                        *protocol.Registry
	initialTimeout                  time.Duration
	gate                            chan struct{}
	mu                              sync.RWMutex
	config                          *model.RuntimeConfig
	records                         map[string]*record
	owned                           map[*record]struct{}
	closed, applying, blocked       bool
	revision, epoch, nextGeneration uint64
	bootID                          string
	fingerprintKey                  [32]byte
	lastOutcome, lastApplyError     string
	errors                          chan error
	once                            sync.Once
	done                            chan struct{}
	closeErr                        error
	watchers                        sync.WaitGroup
}

func Start(ctx context.Context, snapshot *model.RuntimeConfig, registry *protocol.Registry, log *slog.Logger) (*Runtime, error) {
	if ctx == nil || registry == nil {
		return nil, errors.New("runtime context and protocol registry are required")
	}
	normalized, err := registry.Normalize(snapshot)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	r := &Runtime{ctx: ctx, cancel: cancel, registry: registry, initialTimeout: normalized.Config.Limits.ShutdownTimeout, gate: make(chan struct{}, 1),
		records: make(map[string]*record), owned: make(map[*record]struct{}),
		bootID: rand.Text(), errors: make(chan error, 16), done: make(chan struct{})}
	if _, err := rand.Read(r.fingerprintKey[:]); err != nil {
		cancel()
		return nil, err
	}
	if _, err := r.Apply(ctx, normalized); err != nil {
		cleanup, stop := context.WithTimeout(context.Background(), normalized.Config.Limits.ShutdownTimeout)
		defer stop()
		return nil, errors.Join(err, r.Close(cleanup))
	}
	if log != nil {
		log.Info("Node listeners started", "listeners", len(r.records))
	}
	return r, nil
}

func (r *Runtime) timeout() time.Duration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.config != nil {
		return r.config.Config.Limits.ShutdownTimeout
	}
	return r.initialTimeout
}

func (r *Runtime) ShutdownTimeout() time.Duration { return r.timeout() }

// build creates no listening sockets. Owned records include unpublished
// candidates so a failed cleanup cannot make live resources disappear.
func (r *Runtime) build(target *model.RuntimeConfig, spec model.ListenerSpec) (*record, error) {
	factory, _ := r.registry.Lookup(spec.Protocol) // Normalize already resolved it.
	ctx, cancel := context.WithCancel(r.ctx)
	flow := relay.New(ctx, &egress.Direct{}, target.Config.Limits)
	credentials := make(map[string][]byte, len(spec.CredentialRefs))
	for _, ref := range spec.CredentialRefs {
		credentials[ref] = bytes.Clone(target.Credentials[ref])
	}
	factorySpec := spec
	factorySpec.Options = bytes.Clone(spec.Options)
	factorySpec.Network = slices.Clone(spec.Network)
	factorySpec.CredentialRefs = slices.Clone(spec.CredentialRefs)
	cert := target.Certificates[spec.CertificateRef]
	instance, err := factory.Build(protocol.ResolvedListenerSpec{Spec: factorySpec, Limits: target.Config.Limits, Credentials: credentials, Certificate: bytes.Clone(cert.Certificate), PrivateKey: bytes.Clone(cert.PrivateKey)},
		protocol.Dependencies{Handler: flow, Logger: logger.NOP()})
	if err != nil {
		cancel()
		cleanup, stop := context.WithTimeout(context.Background(), target.Config.Limits.ShutdownTimeout)
		defer stop()
		_ = flow.Close(cleanup)
		return nil, fmt.Errorf("listener %q: build: %w", spec.ID, err)
	}
	rec := &record{spec: spec, instance: instance, relay: flow, ctx: ctx, cancel: cancel, state: "prepared", provisional: true,
		fingerprint: r.fingerprint(target, spec)}
	r.mu.Lock()
	r.nextGeneration++
	rec.generation = r.nextGeneration
	r.owned[rec] = struct{}{}
	closed := r.closed
	r.mu.Unlock()
	if closed {
		rec.cancel()
		return rec, ErrClosed
	}
	return rec, nil
}

func (r *Runtime) startRecord(ctx context.Context, rec *record) error {
	r.mu.Lock()
	if r.closed || r.ctx.Err() != nil {
		r.mu.Unlock()
		return ErrClosed
	}
	rec.state = "starting"
	r.records[rec.spec.ID] = rec
	r.epoch++
	r.watchers.Add(1)
	go r.watch(rec)
	r.mu.Unlock()
	// Start receives a lifetime context. Only during initialization does
	// cancellation of the apply operation also cancel this candidate.
	stop := context.AfterFunc(ctx, rec.cancel)
	err := rec.instance.Start(rec.ctx)
	detached := stop()
	if err == nil && !detached {
		err = ctx.Err()
		if err == nil {
			err = context.Canceled
		}
	}
	if err == nil {
		err = ctx.Err()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err == nil && (rec.ctx.Err() != nil || rec.state == "failed") {
		err = errors.New("listener stopped during initialization")
	}
	if err != nil {
		rec.state = "failed"
		rec.lastError = err.Error()
		r.epoch++
		return fmt.Errorf("listener %q: start: %w", rec.spec.ID, err)
	}
	rec.state = "running"
	rec.lastError = ""
	r.epoch++
	return nil
}

func (r *Runtime) watch(rec *record) {
	defer r.watchers.Done()
	for {
		select {
		case <-rec.ctx.Done():
			return
		case event, ok := <-rec.instance.Events():
			var err error
			if !ok {
				err = errors.New("listener event source closed")
			} else if event.Err != nil {
				err = event.Err
			} else if event.State == "stopped" {
				err = errors.New("listener stopped unexpectedly")
			} else {
				continue
			}
			r.mu.Lock()
			if rec.retiring || r.closed || r.records[rec.spec.ID] != rec || rec.ctx.Err() != nil {
				r.mu.Unlock()
				return
			}
			rec.state = "failed"
			rec.lastError = err.Error()
			r.epoch++
			provisional := rec.provisional
			r.mu.Unlock()
			rec.cancel()
			if !provisional {
				select {
				case r.errors <- fmt.Errorf("listener %q generation %d: %w", rec.spec.ID, rec.generation, err):
				default:
				}
			}
			return
		}
	}
}

func (r *Runtime) stopRecord(ctx context.Context, rec *record) error {
	r.mu.Lock()
	rec.retiring = true
	if rec.state != "stopped" {
		rec.state = "stopping"
		r.epoch++
	}
	r.mu.Unlock()
	rec.cancel()
	err := errors.Join(rec.instance.Stop(ctx), rec.relay.Close(ctx))
	r.mu.Lock()
	defer r.mu.Unlock()
	if err == nil {
		rec.state = "stopped"
		delete(r.owned, rec)
	} else {
		rec.state = "failed"
		rec.lastError = err.Error()
	}
	r.epoch++
	return err
}

func (r *Runtime) Errors() <-chan error { return r.errors }

func (r *Runtime) Close(ctx context.Context) error {
	r.once.Do(func() {
		timeout := r.timeout()
		r.mu.Lock()
		r.closed = true
		r.mu.Unlock()
		r.cancel()
		go func() {
			defer close(r.done)
			cleanup, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			acquired := false
			select {
			case r.gate <- struct{}{}:
				acquired = true
			case <-cleanup.Done():
				r.closeErr = cleanup.Err()
			}
			if acquired {
				defer func() { <-r.gate }()
			}
			r.mu.RLock()
			owned := make([]*record, 0, len(r.owned))
			for rec := range r.owned {
				owned = append(owned, rec)
			}
			r.mu.RUnlock()
			for _, rec := range owned {
				r.closeErr = errors.Join(r.closeErr, r.stopRecord(cleanup, rec))
			}
			r.watchers.Wait()
		}()
	})
	select {
	case <-r.done:
		return r.closeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}
