//go:build !linux && !darwin

// SPDX-License-Identifier: GPL-3.0-only
package sqlite

import (
	"errors"
	"os"
)

func acquireLock(string) (*os.File, error) {
	return nil, errors.New("data directory locking is currently supported on Linux and macOS only")
}
