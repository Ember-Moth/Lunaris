// SPDX-License-Identifier: GPL-3.0-only
package web

import (
	"embed"
	"io/fs"
)

// Build the frontend before compiling Go. There is intentionally no fallback UI.
//
//go:embed all:dist
var assets embed.FS

func Files() (fs.FS, error) { return fs.Sub(assets, "dist") }
