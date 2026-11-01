// SPDX-License-Identifier: GPL-3.0-or-later
// Adapted from Polaris; see THIRD_PARTY_NOTICES.md.
package websocket

// Config is the WebSocket carrier shared by the v2ray and gost plugins.
type Config struct {
	Host            string
	Path            string
	Headers         map[string]string
	TLS             bool
	HTTPUpgrade     bool
	EarlyDataHeader string
	MaxEarlyData    int
}
