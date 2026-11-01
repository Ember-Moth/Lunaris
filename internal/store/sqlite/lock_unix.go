//go:build linux || darwin

// SPDX-License-Identifier: GPL-3.0-only
package sqlite

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func acquireLock(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		return nil, fmt.Errorf("data directory is locked or cannot be locked: %w", err)
	}
	return file, nil
}
