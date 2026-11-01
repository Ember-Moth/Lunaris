// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/Ember-Moth/Lunaris/cmd"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := cmd.Run(ctx, os.Args[1:]); err != nil {
		slog.Error("Lunaris stopped", "error", err)
		os.Exit(1)
	}
}
