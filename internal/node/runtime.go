// SPDX-License-Identifier: GPL-3.0-only
package node

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"

	"github.com/Ember-Moth/Lunaris/internal/egress"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/Ember-Moth/Lunaris/internal/relay"
	"github.com/sagernet/sing/common/logger"
)

type record struct {
	id       string
	instance protocol.Instance
	relay    *relay.Handler
}

// Runtime owns one immutable file-mode generation. No HTTP, SQL or frontend
// dependency is needed to construct and run a node.
type Runtime struct {
	ctx      context.Context
	cancel   context.CancelFunc
	limits   model.Limits
	records  []record
	errors   chan error
	once     sync.Once
	done     chan struct{}
	closeErr error
	watchers sync.WaitGroup
}

func Start(ctx context.Context, snapshot *model.RuntimeConfig, registry *protocol.Registry, log *slog.Logger) (_ *Runtime, result error) {
	ctx, cancel := context.WithCancel(ctx)
	runtime := &Runtime{ctx: ctx, cancel: cancel, limits: snapshot.Config.Limits, errors: make(chan error, 1), done: make(chan struct{})}
	defer func() {
		if result != nil {
			cleanup, stop := context.WithTimeout(context.Background(), runtime.limits.ShutdownTimeout)
			defer stop()
			result = errors.Join(result, runtime.Close(cleanup))
		}
	}()
	for _, spec := range snapshot.Config.Listeners {
		if !spec.Enabled {
			continue
		}
		factory, ok := registry.Lookup(spec.Protocol)
		if !ok {
			return nil, fmt.Errorf("listener %q: protocol unavailable", spec.ID)
		}
		if fields := factory.Validate(spec); len(fields) != 0 {
			return nil, fmt.Errorf("listener %q: %s", spec.ID, fields[0].Message)
		}
		spec.Options = bytes.Clone(spec.Options)
		spec.Network = slices.Clone(spec.Network)
		spec.CredentialRefs = slices.Clone(spec.CredentialRefs)
		credentials := make(map[string][]byte, len(spec.CredentialRefs))
		for _, ref := range spec.CredentialRefs {
			credentials[ref] = bytes.Clone(snapshot.Credentials[ref])
		}
		flow := relay.New(ctx, &egress.Direct{}, runtime.limits)
		instance, err := factory.Build(protocol.ResolvedListenerSpec{Spec: spec, Limits: runtime.limits, Credentials: credentials}, protocol.Dependencies{Handler: flow, Logger: logger.NOP()})
		if err != nil {
			cleanup, stop := context.WithTimeout(context.Background(), runtime.limits.ShutdownTimeout)
			defer stop()
			_ = flow.Close(cleanup)
			return nil, fmt.Errorf("listener %q: build: %w", spec.ID, err)
		}
		runtime.records = append(runtime.records, record{id: spec.ID, instance: instance, relay: flow})
	}
	for _, record := range runtime.records {
		if err := record.instance.Start(ctx); err != nil {
			return nil, fmt.Errorf("listener %q: start: %w", record.id, err)
		}
	}
	for _, record := range runtime.records {
		runtime.watchers.Add(1)
		go func() {
			defer runtime.watchers.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case event, ok := <-record.instance.Events():
					if !ok {
						runtime.fail(fmt.Errorf("listener %q: event source closed", record.id))
						return
					}
					if event.Err != nil {
						runtime.fail(fmt.Errorf("listener %q: %w", record.id, event.Err))
						return
					}
					if event.State == "stopped" && ctx.Err() == nil {
						runtime.fail(fmt.Errorf("listener %q stopped unexpectedly", record.id))
						return
					}
				}
			}
		}()
	}
	if log != nil {
		log.Info("Node listeners started", "listeners", len(runtime.records))
	}
	return runtime, nil
}

func (r *Runtime) fail(err error) {
	select {
	case r.errors <- err:
	default:
	}
	r.cancel()
}
func (r *Runtime) Errors() <-chan error { return r.errors }

func (r *Runtime) Close(ctx context.Context) error {
	r.once.Do(func() {
		r.cancel()
		go func() {
			defer close(r.done)
			cleanup, cancel := context.WithTimeout(context.Background(), r.limits.ShutdownTimeout)
			defer cancel()
			for i := len(r.records) - 1; i >= 0; i-- {
				r.closeErr = errors.Join(r.closeErr, r.records[i].instance.Stop(cleanup), r.records[i].relay.Close(cleanup))
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
