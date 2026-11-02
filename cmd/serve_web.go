//go:build webui

// SPDX-License-Identifier: GPL-3.0-only
package cmd

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/admin"
	"github.com/Ember-Moth/Lunaris/internal/auth"
	"github.com/Ember-Moth/Lunaris/internal/config"
	"github.com/Ember-Moth/Lunaris/internal/protocol/builtin"
	"github.com/Ember-Moth/Lunaris/internal/store/sqlite"
	"github.com/Ember-Moth/Lunaris/web"
)

func serve(ctx context.Context, args []string) (result error) {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	configPath := flags.String("config", "", "bootstrap YAML file")
	listen := flags.String("listen", "", "override management listen address")
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
	var tlsConfig *tls.Config
	if options.Admin.TLS != nil {
		load := func(path string) ([]byte, error) {
			f, err := os.Open(path)
			if err != nil {
				return nil, err
			}
			defer f.Close()
			value, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
			if err != nil || len(value) > 1<<20 {
				return nil, errors.New("management TLS asset exceeds 1 MiB")
			}
			return value, nil
		}
		cert, err := load(options.Admin.TLS.CertificateFile)
		if err != nil {
			return errors.New("cannot read management TLS certificate")
		}
		key, err := load(options.Admin.TLS.PrivateKeyFile)
		if err != nil {
			return errors.New("cannot read management TLS private key")
		}
		pair, err := tls.X509KeyPair(cert, key)
		if err != nil {
			return errors.New("invalid management TLS certificate/key pair")
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	}
	raw, err := net.Listen("tcp", options.Admin.Listen)
	if err != nil {
		return fmt.Errorf("bind management listener: %w", err)
	}
	listener := admin.TrackListener(raw)
	defer listener.Close()
	defer listener.CloseConnections()
	repository, err := sqlite.Open(ctx, options.DataDir)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, repository.Close()) }()
	registry, err := builtin.NewRegistry()
	if err != nil {
		return err
	}
	endpoint, err := netip.ParseAddrPort(listener.Addr().String())
	if err != nil {
		return err
	}
	service, err := config.OpenManagementService(ctx, repository, registry, []netip.AddrPort{endpoint})
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), service.ShutdownTimeout())
		defer cancel()
		result = errors.Join(result, service.Close(cleanup))
	}()
	authentication, err := auth.New(repository, options.DataDir)
	if err != nil {
		return err
	}
	expiry, err := authentication.EnsureSetupFile(ctx, false)
	if err != nil {
		return err
	}
	if !expiry.IsZero() {
		slog.Info("Administrator setup requires the private token file", "file", filepath.Join(options.DataDir, auth.SetupFilename), "expires_at", expiry.Format(time.RFC3339))
	}
	origin, err := options.Admin.Origin()
	if err != nil {
		return err
	}
	var trusted []netip.Prefix
	for _, raw := range options.Admin.TrustedProxies {
		prefix, _ := netip.ParsePrefix(raw)
		trusted = append(trusted, prefix.Masked())
	}
	version := admin.Version{Version: "dev", APISchema: "lunaris-management-v1", Frontend: "embedded"}
	if build, ok := debug.ReadBuildInfo(); ok {
		if build.Main.Version != "" && build.Main.Version != "(devel)" {
			version.Version = build.Main.Version
		}
		for _, s := range build.Settings {
			if s.Key == "vcs.revision" {
				version.Commit = s.Value
			}
		}
	}
	assets, err := web.Files()
	if err != nil {
		return err
	}
	index, err := fs.ReadFile(assets, "index.html")
	if err != nil {
		return err
	}
	fingerprint := sha256.Sum256(index)
	version.Frontend = hex.EncodeToString(fingerprint[:16])
	api, err := admin.NewAPI(ctx, admin.APIOptions{Repository: repository, Service: service, Registry: registry, Auth: authentication, Origin: origin, NativeTLS: tlsConfig != nil, TrustedProxies: trusted, Version: version})
	if err != nil {
		return err
	}
	h := admin.New(admin.Options{Listener: listener, Assets: assets, Ready: repository.Ping, API: api, TLS: tlsConfig})
	events, stopSignals := subscribeNodeSignals(ctx)
	defer stopSignals()
	maintenance := time.NewTicker(time.Minute)
	defer maintenance.Stop()
	done := make(chan error, 1)
	go func() { done <- h.Run() }()
	slog.Info("Management service started", "address", listener.Addr().String(), "origin", origin)
	for {
		select {
		case err := <-done:
			return err
		case <-maintenance.C:
			check, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := authentication.Purge(check)
			cancel()
			if err != nil {
				api.Log("warn", "session maintenance could not complete")
			}
		case <-events.reload:
			api.Log("warn", "SIGHUP does not apply management drafts; create and confirm an API plan")
		case <-events.status:
			check, cancel := context.WithTimeout(ctx, time.Second)
			state, err := service.Status(check)
			cancel()
			if err == nil {
				raw, _ := json.Marshal(state)
				slog.Info("Managed node status", "status", string(raw))
			}
		case operation := <-service.OperationEvents():
			level := "info"
			if operation.Status != "succeeded" {
				level = "error"
			}
			api.LogOperation(level, operation.ID, operation.Status)
		case <-service.Errors():
			api.Log("error", "a proxy listener failed; inspect runtime status")
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if h.IsRunning() {
				_ = h.Shutdown(shutdown)
			}
			cancel()
			listener.Close()
			listener.CloseConnections()
			select {
			case err := <-done:
				if err != nil && !errors.Is(err, net.ErrClosed) {
					return err
				}
				return nil
			case <-time.After(time.Second):
				return errors.New("management HTTP accept loop did not stop")
			}
		}
	}
}
