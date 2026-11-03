// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors
// Adapted from Polaris 56d52fb44958ef3cc2a7fb841cd240f8206234b2.
package dns

import "errors"

// Errors reported by the DNS resolver.
var (
	ErrClosed               = errors.New("dns: resolver is closed")
	ErrBusy                 = errors.New("dns: too many pending queries")
	errMalformedMessage     = errors.New("dns: malformed message")
	ErrNoConfiguredResolver = errors.New("dns: no configured resolver")
	ErrServerFailure        = errors.New("dns: server failure")
	ErrTruncatedResponse    = errors.New("dns: truncated response")
)
