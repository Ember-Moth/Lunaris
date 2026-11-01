// Derived from XTLS/Xray-core infra/conf/transport_method.go at b17a88f9b46d.
// Licensed under MPL-2.0; see LICENSES/MPL-2.0/MPL-2.0.txt.

package xhttp

import (
	"crypto/tls"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
)

func (config *Config) normalizeXMUX() error {
	if config.XMUX.MaxConnections.To > 0 && config.XMUX.MaxConcurrency.To > 0 {
		return errors.New("xhttp: xmux maxConnections conflicts with maxConcurrency")
	}
	if config.XMUX == (XMUXConfig{}) {
		config.XMUX.MaxConnections = Range{From: 3, To: 3}
		config.XMUX.HMaxRequestTimes = Range{From: 600, To: 900}
		config.XMUX.HMaxReusableSecs = Range{From: 1800, To: 3000}
	}
	return nil
}

func (config *Config) validateSessionTable() error {
	if config.SessionIDTable == "" {
		return nil
	}
	if predefined, found := predefinedTables[config.SessionIDTable]; found {
		config.SessionIDTable = predefined
	}
	if config.SessionIDLength.From <= 0 {
		return errors.New("xhttp: sessionIDLength.from must be positive")
	}
	for index := range len(config.SessionIDTable) {
		if config.SessionIDTable[index] >= 0x80 {
			return errors.New("xhttp: sessionIDTable must be ASCII")
		}
	}
	room := new(big.Int)
	base := big.NewInt(int64(len(config.SessionIDTable)))
	for length := config.SessionIDLength.From; length <= config.SessionIDLength.To; length++ {
		room.Add(room, new(big.Int).Exp(base, big.NewInt(int64(length)), nil))
	}
	if room.Cmp(big.NewInt(2<<30)) < 0 {
		return errors.New("xhttp: session ID space is too small")
	}
	return nil
}

func buildDownload(raw rawStreamConfig) (*DownloadConfig, error) {
	network := strings.ToLower(raw.Network)
	if raw.Method != "" {
		network = strings.ToLower(raw.Method)
	}
	if network != "xhttp" && network != "splithttp" {
		return nil, errors.New("xhttp: downloadSettings must use xhttp")
	}
	nested := raw.XHTTPSettings
	if nested == nil {
		nested = raw.SplitHTTPSettings
	}
	if nested == nil {
		return nil, errors.New("xhttp: missing download xhttpSettings")
	}
	transport, err := buildConfig(*nested)
	if err != nil {
		return nil, fmt.Errorf("xhttp: download settings: %w", err)
	}
	if raw.Address == "" || raw.Port == 0 {
		return nil, errors.New("xhttp: incomplete download destination")
	}
	address := net.JoinHostPort(raw.Address, strconv.FormatUint(uint64(raw.Port), 10))
	var tlsConfig *tls.Config
	switch strings.ToLower(raw.Security) {
	case "", "none":
	case "tls":
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS12, ServerName: raw.TLSSettings.ServerName,
			InsecureSkipVerify: raw.TLSSettings.AllowInsecure, //nolint:gosec // AllowInsecure is the operator's choice
			NextProtos:         raw.TLSSettings.ALPN,
		}
	default:
		return nil, fmt.Errorf("xhttp: unsupported download security %q", raw.Security)
	}
	return &DownloadConfig{Address: address, TLSConfig: tlsConfig, Transport: transport}, nil
}

func oneOf(value string, allowed ...string) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}

var predefinedTables = map[string]string{
	"ALPHABET": "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "Alphabet": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
	"BASE36": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"Base62": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
	"HEX":    "0123456789ABCDEF", "alphabet": "abcdefghijklmnopqrstuvwxyz",
	"base36": "0123456789abcdefghijklmnopqrstuvwxyz", "hex": "0123456789abcdef", "number": "0123456789",
}
