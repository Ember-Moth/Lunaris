// SPDX-License-Identifier: GPL-3.0-or-later
// Adapted from Polaris; see THIRD_PARTY_NOTICES.md.
package plugin

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"

	"github.com/Ember-Moth/Lunaris/internal/transport/ssplugin/gost"
	"github.com/Ember-Moth/Lunaris/internal/transport/ssplugin/v2ray"
	carrier "github.com/Ember-Moth/Lunaris/internal/transport/ssplugin/websocket"
)

func parseV2RayPlugin(values *pluginValues) (v2ray.Config, error) {
	websocket, mux, err := parseWebSocket(values)
	if err != nil {
		return v2ray.Config{}, err
	}
	if websocket.HTTPUpgrade, err = values.boolean("v2ray-http-upgrade", false); err != nil {
		return v2ray.Config{}, err
	}
	config := v2ray.Config{WebSocket: websocket, Mux: mux}
	if config.MaxSessions, err = parsePluginLimit(values, "max-sessions", 65535, "max_sessions"); err != nil {
		return v2ray.Config{}, err
	}
	if config.MaxSessionQueuedBytes, err = parsePluginLimit(values, "max-session-queued-bytes", 64*1024*1024,
		"max_session_queued_bytes"); err != nil {
		return v2ray.Config{}, err
	}
	if config.MaxQueuedBytes, err = parsePluginLimit(values, "max-queued-bytes", 256*1024*1024,
		"max_queued_bytes"); err != nil {
		return v2ray.Config{}, err
	}
	if config.MaxActiveStreams, err = parsePluginLimit(values, "max-active-streams", 1<<20,
		"max_active_streams"); err != nil {
		return v2ray.Config{}, err
	}
	handshakeSeconds, err := parsePluginLimit(values, "handshake-timeout", 300, "handshake_timeout")
	if err != nil {
		return v2ray.Config{}, err
	}
	config.HandshakeTimeout = time.Duration(handshakeSeconds) * time.Second
	if config.MaxSessionQueuedBytes > 0 && config.MaxQueuedBytes > 0 &&
		config.MaxSessionQueuedBytes > config.MaxQueuedBytes {
		return v2ray.Config{}, values.invalid("max-session-queued-bytes")
	}
	return config, nil
}

func parseGostPlugin(values *pluginValues) (gost.Config, error) {
	websocket, mux, err := parseWebSocket(values)
	if err != nil {
		return gost.Config{}, err
	}
	config := gost.Config{WebSocket: websocket, Mux: mux}
	if config.MaxStreams, err = parsePluginLimit(values, "max-streams", 65535, "max_streams"); err != nil {
		return gost.Config{}, err
	}
	if config.MaxActiveStreams, err = parsePluginLimit(values, "max-active-streams", 1<<20,
		"max_active_streams"); err != nil {
		return gost.Config{}, err
	}
	handshakeSeconds, err := parsePluginLimit(values, "handshake-timeout", 300, "handshake_timeout")
	if err != nil {
		return gost.Config{}, err
	}
	config.HandshakeTimeout = time.Duration(handshakeSeconds) * time.Second
	return config, nil
}

func parsePluginLimit(values *pluginValues, field string, maximum int, aliases ...string) (int, error) {
	value, err := values.integer(field, 0, aliases...)
	if err != nil || value < 0 || value > maximum {
		return 0, values.invalid(field)
	}
	return value, nil
}

func parseWebSocket(values *pluginValues) (carrier.Config, bool, error) {
	mode, err := values.string("mode", "", true)
	if err != nil || !strings.EqualFold(strings.TrimSpace(mode), "websocket") {
		return carrier.Config{}, false, values.invalid("mode")
	}
	config := carrier.Config{}
	if config.Host, err = values.string("host", "", false); err != nil {
		return config, false, err
	}
	rawPath, err := values.string("path", "/", false)
	if err != nil {
		return config, false, err
	}
	parsedPath, err := url.ParseRequestURI(rawPath)
	if err != nil || !strings.HasPrefix(parsedPath.Path, "/") {
		return config, false, values.invalid("path")
	}
	if len(rawPath) > 1024 || strings.HasPrefix(parsedPath.Path, "//") || parsedPath.Fragment != "" {
		return config, false, values.invalid("path")
	}
	query, err := url.ParseQuery(parsedPath.RawQuery)
	if err != nil || len(query) > 1 || len(query) > 0 && (len(query["ed"]) != 1 || query.Get("ed") == "") {
		return config, false, values.invalid("path")
	}
	config.Path = parsedPath.EscapedPath()
	if earlyData := parsedPath.Query().Get("ed"); earlyData != "" {
		config.MaxEarlyData, err = strconv.Atoi(earlyData)
		if err != nil || config.MaxEarlyData <= 0 || config.MaxEarlyData > 65535 {
			return config, false, values.invalid("path")
		}
		config.EarlyDataHeader = "Sec-WebSocket-Protocol"
	}
	if config.TLS, err = values.boolean("tls", false); err != nil {
		return config, false, err
	}
	mux, err := values.boolean("mux", true)
	if err != nil {
		return config, false, err
	}
	if config.Headers, err = values.stringMap("headers"); err != nil {
		return config, false, err
	}
	if err := normalizeHeaders(&config); err != nil {
		return config, false, values.invalid("headers")
	}
	return config, mux, nil
}

func normalizeHeaders(config *carrier.Config) error {
	normalized := make(map[string]string, len(config.Headers))
	for name, value := range config.Headers {
		if !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(value) {
			return ErrInvalidOption
		}
		if strings.EqualFold(name, "Host") {
			if config.Host != "" && config.Host != value {
				return ErrInvalidOption
			}
			config.Host = value
			continue
		}
		canonical := http.CanonicalHeaderKey(name)
		if _, exists := normalized[canonical]; exists {
			return ErrInvalidOption
		}
		normalized[canonical] = value
	}
	config.Headers = normalized
	if strings.TrimSpace(config.Host) != config.Host || !httpguts.ValidHostHeader(config.Host) || strings.ContainsAny(config.Host, "\r\n\t /\\") {
		return ErrInvalidOption
	}
	return nil
}
