//go:build !webui

// SPDX-License-Identifier: GPL-3.0-only
package cmd

import (
	"context"
	"errors"
)

func serve(context.Context, []string) error {
	return errors.New("management API is not included in this build; use managed for committed SQLite configuration, or make build-web")
}
