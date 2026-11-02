// SPDX-License-Identifier: GPL-3.0-only
package cmd

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/auth"
	"github.com/Ember-Moth/Lunaris/internal/store/sqlite"
)

func runAdmin(ctx context.Context, args []string) (result error) {
	if len(args) == 0 {
		return errors.New("usage: admin <setup-token|reset-password> --data-dir DIR [--password-file FILE]")
	}
	action := args[0]
	if action != "setup-token" && action != "reset-password" {
		return errors.New("unknown admin recovery command")
	}
	flags := flag.NewFlagSet("admin "+action, flag.ContinueOnError)
	dir := flags.String("data-dir", "./data", "node data directory (stop the running node first)")
	file := flags.String("password-file", "", "private regular file containing the new administrator password")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected admin recovery arguments")
	}
	if action == "reset-password" && *file == "" || action == "setup-token" && *file != "" {
		return errors.New("password-file is required only for reset-password")
	}
	repository, err := sqlite.Open(ctx, *dir)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, repository.Close()) }()
	authentication, err := auth.New(repository, *dir)
	if err != nil {
		return err
	}
	if action == "setup-token" {
		expires, err := authentication.EnsureSetupFile(ctx, true)
		if err != nil {
			return err
		}
		fmt.Printf("Setup token file: %s (expires %s)\n", filepath.Join(*dir, auth.SetupFilename), expires.Format(time.RFC3339))
		return nil
	}
	f, err := os.Open(*file)
	if err != nil {
		return errors.New("cannot open administrator password file")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return errors.New("password file must be a private regular file (0600)")
	}
	value, err := io.ReadAll(io.LimitReader(f, 1027))
	if err != nil {
		return errors.New("cannot read password file")
	}
	value = bytes.TrimSuffix(bytes.TrimSuffix(value, []byte("\n")), []byte("\r"))
	if err := authentication.ResetPassword(ctx, string(value)); err != nil {
		return err
	}
	fmt.Println("Administrator password reset; all sessions revoked.")
	return nil
}
