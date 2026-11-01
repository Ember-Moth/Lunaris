// SPDX-License-Identifier: GPL-3.0-only
package model

import (
	"errors"
	"fmt"
	"time"
)

func ValidateLimits(l Limits) error {
	for name, duration := range map[string]time.Duration{"dial_timeout": l.DialTimeout, "handshake_timeout": l.HandshakeTimeout, "udp_idle_timeout": l.UDPIdleTimeout, "shutdown_timeout": l.ShutdownTimeout} {
		if duration <= 0 || duration > 24*time.Hour {
			return fmt.Errorf("%s must be positive and no greater than 24h", name)
		}
	}
	for name, count := range map[string]int{"max_connections": l.MaxConnections, "max_pending_handshakes": l.MaxPendingHandshakes, "max_udp_sessions": l.MaxUDPSessions, "max_udp_destinations": l.MaxUDPDestinations} {
		if count <= 0 || count > 65536 {
			return fmt.Errorf("%s must be between 1 and 65536", name)
		}
	}
	if l.UDPQueueSize <= 0 || l.UDPQueueSize > 1024 {
		return errors.New("udp_queue_size must be between 1 and 1024")
	}
	return nil
}
