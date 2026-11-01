// SPDX-License-Identifier: GPL-3.0-only
package cmd

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/Ember-Moth/Lunaris/internal/config"
	"github.com/Ember-Moth/Lunaris/internal/node"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
)

type nodeSignals struct{ reload, status <-chan struct{} }
type reloadResult struct {
	result node.ApplyResult
	err    error
}

// Reload work runs outside the signal loop. Status and shutdown stay responsive,
// and repeated reload requests coalesce into one additional read of the file.
func watchNode(ctx context.Context, path string, registry *protocol.Registry, runtime *node.Runtime, events nodeSignals, log *slog.Logger) error {
	results := make(chan reloadResult, 1)
	busy, pending := false, false
	start := func() {
		busy = true
		go func() {
			out := reloadResult{result: node.ApplyResult{Outcome: "rejected"}}
			snapshot, err := config.LoadNode(path, registry)
			if err == nil {
				out.result, err = runtime.Apply(ctx, snapshot)
			}
			out.err = err
			select {
			case results <- out:
			case <-ctx.Done():
			}
		}()
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-events.reload:
			if busy {
				pending = true
			} else {
				start()
			}
		case <-events.status:
			status, _ := json.Marshal(runtime.Snapshot())
			log.Info("Node runtime status", "status", string(status))
		case err := <-runtime.Errors():
			log.Error("Node listener failed; other listeners remain available", "error", err)
		case outcome := <-results:
			busy = false
			state := runtime.Snapshot()
			if outcome.err != nil {
				log.Warn("Node configuration reload failed", "outcome", outcome.result.Outcome, "revision", state.Revision, "recovery_required", state.RecoveryRequired, "error", outcome.err)
			} else {
				log.Info("Node configuration reloaded", "outcome", outcome.result.Outcome, "revision", state.Revision, "changes", outcome.result.Plan.Changes)
			}
			if pending && ctx.Err() == nil {
				pending = false
				start()
			}
		}
	}
}
