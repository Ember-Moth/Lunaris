// Derived from XTLS/Xray-core infra/conf/transport_method.go at b17a88f9b46d.
// Licensed under MPL-2.0; see LICENSES/MPL-2.0/MPL-2.0.txt.

package xhttp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Parse builds the validated configuration from the panel's host, path, mode and
// extra JSON.
func Parse(host, path, mode, extra string) (Config, error) {
	var raw rawConfig
	if strings.TrimSpace(extra) != "" {
		if err := json.Unmarshal([]byte(extra), &raw); err != nil {
			return Config{}, fmt.Errorf("xhttp: parse extra: %w", err)
		}
	}
	raw.Host, raw.Path, raw.Mode = host, path, mode
	return buildConfig(raw)
}

func buildConfig(raw rawConfig) (Config, error) {
	if len(raw.Extra) > 0 {
		var extra rawConfig
		if err := json.Unmarshal(raw.Extra, &extra); err != nil {
			return Config{}, fmt.Errorf("xhttp: parse nested extra: %w", err)
		}
		extra.Host, extra.Path, extra.Mode = raw.Host, raw.Path, raw.Mode
		raw = extra
	}
	config := Config{
		Host: raw.Host, Path: raw.Path, Mode: raw.Mode, ServerBackend: raw.ServerBackend, Headers: raw.Headers,
		XPaddingBytes: raw.XPaddingBytes, XPaddingObfsMode: raw.XPaddingObfsMode,
		XPaddingKey: raw.XPaddingKey, XPaddingHeader: raw.XPaddingHeader,
		XPaddingPlacement: raw.XPaddingPlacement, XPaddingMethod: raw.XPaddingMethod,
		UplinkHTTPMethod: raw.UplinkHTTPMethod, SessionIDPlacement: raw.SessionIDPlacement,
		SessionIDKey: raw.SessionIDKey, SessionIDTable: raw.SessionIDTable,
		SessionIDLength: raw.SessionIDLength, SeqPlacement: raw.SeqPlacement, SeqKey: raw.SeqKey,
		UplinkDataPlacement: raw.UplinkDataPlacement, UplinkDataKey: raw.UplinkDataKey,
		UplinkChunkSize: raw.UplinkChunkSize, NoGRPCHeader: raw.NoGRPCHeader,
		NoSSEHeader: raw.NoSSEHeader, ScMaxEachPostBytes: raw.ScMaxEachPostBytes,
		ScMinPostsIntervalMs: raw.ScMinPostsIntervalMs, ScMaxBufferedPosts: int(raw.ScMaxBufferedPosts),
		ScMaxBufferedBytes:               raw.ScMaxBufferedBytes,
		ScMaxTotalBufferedBytes:          raw.ScMaxTotalBufferedBytes,
		ScMaxActiveSessions:              int(raw.ScMaxActiveSessions),
		ScMaxConcurrentRequests:          int(raw.ScMaxConcurrentRequests),
		ScStreamUpServerSecs:             raw.ScStreamUpServerSecs,
		ServerMaxHeaderBytes:             int(raw.ServerMaxHeaderBytes),
		H3InitialStreamReceiveWindow:     raw.H3InitialStreamReceiveWindow,
		H3MaxStreamReceiveWindow:         raw.H3MaxStreamReceiveWindow,
		H3InitialConnectionReceiveWindow: raw.H3InitialConnectionReceiveWindow,
		H3MaxConnectionReceiveWindow:     raw.H3MaxConnectionReceiveWindow,
		XMUX:                             raw.XMUX,
	}
	if err := config.normalize(); err != nil {
		return Config{}, err
	}
	if raw.DownloadSettings != nil {
		download, err := buildDownload(*raw.DownloadSettings)
		if err != nil {
			return Config{}, err
		}
		if config.Mode == ModeStreamOne {
			return Config{}, errors.New("xhttp: downloadSettings is incompatible with stream-one")
		}
		config.Download = download
	}
	return config, nil
}

func (config *Config) normalize() error {
	if config.Mode == "" {
		config.Mode = ModeAuto
	}
	if config.Mode != ModeAuto && config.Mode != ModePacketUp && config.Mode != ModeStreamUp &&
		config.Mode != ModeStreamOne {
		return fmt.Errorf("xhttp: unsupported mode %q", config.Mode)
	}
	// net/http is the only server backend. A configured value is rejected rather
	// than ignored, so a node that was pinned to the removed fasthttp backend
	// fails loudly instead of silently changing behaviour.
	if config.ServerBackend != "" && config.ServerBackend != ServerBackendNetHTTP {
		return fmt.Errorf("xhttp: unsupported server backend %q", config.ServerBackend)
	}
	if strings.ContainsAny(config.Host, "\r\n") {
		return errors.New("xhttp: invalid host")
	}
	for key := range config.Headers {
		if strings.EqualFold(key, "host") {
			return errors.New("xhttp: headers cannot contain host")
		}
	}
	if !config.XPaddingBytes.zero() && (config.XPaddingBytes.From <= 0 || config.XPaddingBytes.To <= 0) {
		return errors.New("xhttp: xPaddingBytes cannot be disabled")
	}
	if config.XPaddingBytes.zero() {
		config.XPaddingBytes = Range{From: 100, To: 1000}
	}
	if config.XPaddingKey == "" {
		config.XPaddingKey = "x_padding"
	}
	if config.XPaddingHeader == "" {
		config.XPaddingHeader = "X-Padding"
	}
	if config.XPaddingPlacement == "" {
		config.XPaddingPlacement = PlacementQueryInHeader
	}
	if !oneOf(config.XPaddingPlacement, PlacementCookie, PlacementHeader, PlacementQuery, PlacementQueryInHeader) {
		return fmt.Errorf("xhttp: unsupported padding placement %q", config.XPaddingPlacement)
	}
	if config.XPaddingMethod == "" {
		config.XPaddingMethod = PaddingRepeatX
	}
	if !oneOf(config.XPaddingMethod, PaddingRepeatX, PaddingTokenish) {
		return fmt.Errorf("xhttp: unsupported padding method %q", config.XPaddingMethod)
	}
	return config.normalizeRequestControls()
}

func (config *Config) normalizeRequestControls() error {
	if config.UplinkDataPlacement == "" {
		config.UplinkDataPlacement = PlacementAuto
	}
	if !oneOf(config.UplinkDataPlacement, PlacementAuto, PlacementBody, PlacementCookie, PlacementHeader) {
		return fmt.Errorf("xhttp: unsupported uplink data placement %q", config.UplinkDataPlacement)
	}
	if oneOf(config.UplinkDataPlacement, PlacementCookie, PlacementHeader) && config.Mode != ModePacketUp {
		return errors.New("xhttp: header/cookie uplink data requires packet-up")
	}
	if config.UplinkHTTPMethod == "" {
		config.UplinkHTTPMethod = http.MethodPost
	}
	config.UplinkHTTPMethod = strings.ToUpper(config.UplinkHTTPMethod)
	if config.UplinkHTTPMethod == http.MethodGet && config.Mode != ModePacketUp {
		return errors.New("xhttp: GET uplink requires packet-up")
	}
	if config.SessionIDPlacement == "" {
		config.SessionIDPlacement = PlacementPath
	}
	if config.SeqPlacement == "" {
		config.SeqPlacement = PlacementPath
	}
	if !oneOf(config.SessionIDPlacement, PlacementPath, PlacementCookie, PlacementHeader, PlacementQuery) ||
		!oneOf(config.SeqPlacement, PlacementPath, PlacementCookie, PlacementHeader, PlacementQuery) {
		return errors.New("xhttp: unsupported session or sequence placement")
	}
	config.defaultKeys()
	if err := config.validateSessionTable(); err != nil {
		return err
	}
	if config.ServerMaxHeaderBytes < 0 {
		return errors.New("xhttp: negative serverMaxHeaderBytes")
	}
	if err := config.normalizeH3ReceiveWindows(); err != nil {
		return err
	}
	if !config.ScMaxEachPostBytes.zero() && config.ScMaxEachPostBytes.From <= 0 {
		return errors.New("xhttp: scMaxEachPostBytes must be positive")
	}
	if config.ScMaxBufferedPosts < 0 {
		return errors.New("xhttp: scMaxBufferedPosts must not be negative")
	}
	if config.ScMaxActiveSessions < 0 {
		return errors.New("xhttp: scMaxActiveSessions must not be negative")
	}
	if config.ScMaxActiveSessions > maximumActiveSessions {
		return errors.New("xhttp: scMaxActiveSessions is too large")
	}
	if config.ScMaxConcurrentRequests < 0 || config.ScMaxConcurrentRequests > maximumConcurrentRequests {
		return errors.New("xhttp: invalid scMaxConcurrentRequests")
	}
	if config.ScMaxBufferedBytes < 0 || config.ScMaxTotalBufferedBytes < 0 {
		return errors.New("xhttp: buffered byte limits must not be negative")
	}
	config.defaultLimits()
	return config.normalizeXMUX()
}

func (config *Config) normalizeH3ReceiveWindows() error {
	if config.H3InitialStreamReceiveWindow == 0 {
		config.H3InitialStreamReceiveWindow = h3InitialStreamReceiveWindow
	}
	if config.H3MaxStreamReceiveWindow == 0 {
		config.H3MaxStreamReceiveWindow = h3MaxStreamReceiveWindow
	}
	if config.H3InitialConnectionReceiveWindow == 0 {
		config.H3InitialConnectionReceiveWindow = h3InitialConnectionReceiveWindow
	}
	if config.H3MaxConnectionReceiveWindow == 0 {
		config.H3MaxConnectionReceiveWindow = h3MaxConnectionReceiveWindow
	}
	if config.H3InitialStreamReceiveWindow < 0 || config.H3MaxStreamReceiveWindow < 0 ||
		config.H3InitialConnectionReceiveWindow < 0 || config.H3MaxConnectionReceiveWindow < 0 {
		return errors.New("xhttp: HTTP/3 receive windows must be positive")
	}
	if config.H3InitialStreamReceiveWindow > config.H3MaxStreamReceiveWindow ||
		config.H3InitialConnectionReceiveWindow > config.H3MaxConnectionReceiveWindow {
		return errors.New("xhttp: HTTP/3 initial receive window exceeds maximum")
	}
	if config.H3InitialConnectionReceiveWindow < config.H3InitialStreamReceiveWindow ||
		config.H3MaxConnectionReceiveWindow < config.H3MaxStreamReceiveWindow {
		return errors.New("xhttp: HTTP/3 connection receive window is smaller than stream window")
	}
	return nil
}

func (config *Config) defaultKeys() {
	if config.SessionIDKey == "" && config.SessionIDPlacement != PlacementPath {
		if config.SessionIDPlacement == PlacementHeader {
			config.SessionIDKey = "X-Session"
		} else {
			config.SessionIDKey = "x_session"
		}
	}
	if config.SeqKey == "" && config.SeqPlacement != PlacementPath {
		if config.SeqPlacement == PlacementHeader {
			config.SeqKey = "X-Seq"
		} else {
			config.SeqKey = "x_seq"
		}
	}
	if config.UplinkDataKey == "" && config.UplinkDataPlacement != PlacementBody {
		if config.UplinkDataPlacement == PlacementCookie {
			config.UplinkDataKey = "x_data"
		} else {
			config.UplinkDataKey = "X-Data"
		}
	}
}

func (config *Config) defaultLimits() {
	if config.ScMaxEachPostBytes.zero() {
		config.ScMaxEachPostBytes = Range{From: 1_000_000, To: 1_000_000}
	}
	if config.ScMinPostsIntervalMs.zero() {
		config.ScMinPostsIntervalMs = Range{From: 30, To: 30}
	}
	if config.ScMaxBufferedPosts == 0 {
		config.ScMaxBufferedPosts = 30
	}
	if config.ScMaxBufferedBytes == 0 {
		config.ScMaxBufferedBytes = 4 << 20
	}
	if config.ScMaxTotalBufferedBytes == 0 {
		config.ScMaxTotalBufferedBytes = 256 << 20
	}
	if config.ScMaxTotalBufferedBytes < config.ScMaxBufferedBytes {
		config.ScMaxTotalBufferedBytes = config.ScMaxBufferedBytes
	}
	maxPostBytes := int64(config.ScMaxEachPostBytes.To)
	if config.ScMaxBufferedBytes < maxPostBytes {
		config.ScMaxBufferedBytes = maxPostBytes
	}
	if config.ScMaxTotalBufferedBytes < maxPostBytes {
		config.ScMaxTotalBufferedBytes = maxPostBytes
	}
	if config.ScMaxActiveSessions == 0 {
		config.ScMaxActiveSessions = defaultMaxActiveSessions
	}
	if config.ScMaxConcurrentRequests == 0 {
		config.ScMaxConcurrentRequests = defaultMaxConcurrentRequests
	}
	if config.ScStreamUpServerSecs.zero() {
		config.ScStreamUpServerSecs = Range{From: 20, To: 80}
	}
	if config.ServerMaxHeaderBytes == 0 {
		config.ServerMaxHeaderBytes = 8192
	}
	if config.UplinkChunkSize.zero() {
		switch config.UplinkDataPlacement {
		case PlacementCookie:
			config.UplinkChunkSize = Range{From: 2048, To: 3072}
		case PlacementHeader:
			config.UplinkChunkSize = Range{From: 3000, To: 4000}
		default:
			config.UplinkChunkSize = config.ScMaxEachPostBytes
		}
	} else if config.UplinkChunkSize.From < 64 {
		config.UplinkChunkSize.From = 64
		config.UplinkChunkSize.To = max(64, config.UplinkChunkSize.To)
	}
}
