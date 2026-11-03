//go:build !linux && !darwin

// SPDX-License-Identifier: GPL-3.0-only
package ingress

import (
	"errors"
	"net"
	"net/netip"
)

func enableUDPDestination(*net.UDPConn) error {
	return errors.New("wildcard UDP source preservation requires Linux or macOS")
}
func readUDPDestination(*net.UDPConn, []byte) (int, netip.AddrPort, netip.Addr, error) {
	return 0, netip.AddrPort{}, netip.Addr{}, errors.New("UDP destination metadata unsupported")
}
func marshalUDPSource(netip.Addr, bool) []byte { return nil }
