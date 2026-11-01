//go:build !linux && !darwin

// SPDX-License-Identifier: GPL-3.0-only
package cmd

import "context"

func subscribeNodeSignals(context.Context) (nodeSignals, func()) { return nodeSignals{}, func() {} }
