//go:build !webui

// SPDX-License-Identifier: GPL-3.0-only
package cmd

import (
	"context"
	"errors"
)

func serve(context.Context, []string) error {
	return errors.New("management API is not included in this build; use run for the node core, or make build-web")
}
