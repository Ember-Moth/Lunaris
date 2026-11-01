// SPDX-License-Identifier: GPL-3.0-only
package cmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/admin"
	"github.com/Ember-Moth/Lunaris/internal/config"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/Ember-Moth/Lunaris/internal/store/sqlite"
	"github.com/Ember-Moth/Lunaris/web"
)

func Run(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		fmt.Println("Usage: lunaris serve [--config FILE] [--listen ADDRESS] [--data-dir DIR]\n       lunaris version")
		return nil
	}
	switch args[0] {
	case "version":
		version := "dev"
		if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
			version = info.Main.Version
		}
		fmt.Println("Lunaris", version)
		return nil
	case "serve":
		return serve(ctx, args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func serve(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	configPath := flags.String("config", "", "bootstrap YAML file")
	listen := flags.String("listen", "", "override loopback management address")
	dataDir := flags.String("data-dir", "", "override local data directory")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("serve does not accept positional arguments")
	}
	options := config.Defaults()
	if *configPath != "" {
		loaded, err := config.Load(*configPath)
		if err != nil {
			return err
		}
		options = loaded
	}
	if *listen != "" {
		options.Admin.Listen = *listen
	}
	if *dataDir != "" {
		options.DataDir = *dataDir
	}
	if err := options.Validate(); err != nil {
		return err
	}
	store, err := sqlite.Open(ctx, options.DataDir)
	if err != nil {
		return err
	}
	defer store.Close()
	registry, err := protocol.NewRegistry()
	if err != nil {
		return err
	}
	assets, err := web.Files()
	if err != nil {
		return err
	}
	rawListener, err := net.Listen("tcp", options.Admin.Listen)
	if err != nil {
		return fmt.Errorf("bind management listener: %w", err)
	}
	listener := admin.TrackListener(rawListener)
	defer listener.Close()
	defer listener.CloseConnections()
	h := admin.New(admin.Options{Listener: listener, Assets: assets, Ready: store.Ping})
	slog.Info("Starting management service", "address", listener.Addr().String(), "protocols", len(registry.Capabilities()))
	result := make(chan error, 1)
	go func() { result <- h.Run() }()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if h.IsRunning() {
			if err := h.Shutdown(shutdownCtx); err != nil {
				slog.Warn("Graceful shutdown failed", "error", err)
			}
		}
		// Close the pre-bound listener even if cancellation raced engine startup.
		listener.Close()
		listener.CloseConnections()
		// Draining may consume its full deadline. Waiting for the already-stopped
		// accept loop must not race against that expired context.
		stopCtx, stopCancel := context.WithTimeout(context.Background(), time.Second)
		defer stopCancel()
		select {
		case err := <-result:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				return err
			}
		case <-stopCtx.Done():
			return stopCtx.Err()
		}
		return nil
	}
}
