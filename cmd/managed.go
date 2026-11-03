// SPDX-License-Identifier: GPL-3.0-only
package cmd

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"log/slog"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/config"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol/builtin"
	"github.com/Ember-Moth/Lunaris/internal/store/sqlite"
)

func runManaged(ctx context.Context, args []string) (result error) {
	flags := flag.NewFlagSet("managed", flag.ContinueOnError)
	dir := flags.String("data-dir", "./data", "managed node data directory")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("managed does not accept positional arguments")
	}
	registry, err := builtin.NewRegistry()
	if err != nil {
		return err
	}
	store, err := sqlite.Open(ctx, *dir)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, store.Close()) }()
	events, stopSignals := subscribeNodeSignals(ctx)
	defer stopSignals()
	service, err := config.OpenService(ctx, store, registry, true)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), service.ShutdownTimeout())
		defer cancel()
		result = errors.Join(result, service.Close(cleanup))
	}()
	status, err := service.Status(ctx)
	if err != nil {
		return err
	}
	slog.Info("Managed node started", "committed_revision", status.Heads.CommittedRevision, "draft_revision", status.Heads.DraftRevision, "listeners", len(status.Runtime.Listeners))
	type completion struct {
		operation model.ApplyOperation
		err       error
	}
	results := make(chan completion, 1)
	busy, pending := false, false
	start := func() {
		busy = true
		go func() {
			var completed completion
			heads, err := store.Heads(ctx)
			if err == nil {
				completed.operation, err = service.Apply(ctx, "signal_"+rand.Text(), heads.DraftRevision, "")
			}
			completed.err = err
			select {
			case results <- completed:
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
			query, cancel := context.WithTimeout(ctx, time.Second)
			status, err := service.Status(query)
			cancel()
			encoded, _ := json.Marshal(status)
			slog.Info("Managed node status", "status", string(encoded))
			if err != nil {
				slog.Warn("Persisted status unavailable", "error", err)
			}
		case err := <-service.Errors():
			slog.Error("Managed listener failed", "error", err)
		case completed := <-results:
			busy = false
			if completed.err != nil {
				slog.Warn("Managed application failed", "operation_id", completed.operation.ID, "status", completed.operation.Status, "error", completed.err)
			} else {
				slog.Info("Managed configuration committed", "operation_id", completed.operation.ID, "revision", completed.operation.TargetRevision)
			}
			if pending && ctx.Err() == nil {
				pending = false
				start()
			}
		}
	}
}
