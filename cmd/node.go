// SPDX-License-Identifier: GPL-3.0-only
package cmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"

	"github.com/Ember-Moth/Lunaris/internal/config"
	"github.com/Ember-Moth/Lunaris/internal/node"
	"github.com/Ember-Moth/Lunaris/internal/protocol/builtin"
)

func runNode(ctx context.Context, args []string, checkOnly bool) error {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	path := flags.String("config", "", "node YAML configuration (required)")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 || *path == "" {
		return errors.New("use --config to select a node YAML file")
	}
	registry, err := builtin.NewRegistry()
	if err != nil {
		return err
	}
	snapshot, err := config.LoadNode(*path, registry)
	if err != nil {
		return err
	}
	if checkOnly {
		fmt.Printf("Configuration valid: %d listener(s)\n", len(snapshot.Config.Listeners))
		return nil
	}
	events, stopSignals := subscribeNodeSignals(ctx)
	defer stopSignals()
	runtime, err := node.Start(ctx, snapshot, registry, slog.Default())
	if err != nil {
		return err
	}
	err = watchNode(ctx, *path, registry, runtime, events, slog.Default())
	cleanup, cancel := context.WithTimeout(context.Background(), runtime.ShutdownTimeout())
	defer cancel()
	return errors.Join(err, runtime.Close(cleanup))
}
