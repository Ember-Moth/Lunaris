//go:build !linux

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors
// Adapted from Polaris 56d52fb44958ef3cc2a7fb841cd240f8206234b2.
package ingress

import "net"

func peekProxyHeader(net.Conn, []byte, bool) (n int, supported bool, wouldBlock bool, err error) {
	return 0, false, false, nil
}
