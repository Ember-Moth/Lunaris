// SPDX-License-Identifier: GPL-3.0-or-later
// Adapted from Polaris; see THIRD_PARTY_NOTICES.md.
package plugin

import (
	"net"
	"strconv"
	"strings"

	"github.com/Ember-Moth/Lunaris/internal/transport/ssplugin/restls"
	"github.com/Ember-Moth/Lunaris/internal/transport/ssplugin/shadowtls"
)

func parseShadowTLSPlugin(values *pluginValues) (shadowtls.Config, error) {
	config := shadowtls.Config{}
	var err error
	if config.Version, err = values.integer("version", 2); err != nil || config.Version < 1 || config.Version > 3 {
		return config, values.invalid("version")
	}
	if config.Password, err = values.string("password", "", config.Version > 1); err != nil {
		return config, err
	}
	if config.StrictMode, err = values.boolean("strict-mode", false, "strict_mode", "strict"); err != nil {
		return config, err
	}
	if config.HandshakeAddress, err = values.string("handshake", "", true, "dest"); err != nil {
		return config, err
	}
	if !validAddress(config.HandshakeAddress) {
		return config, values.invalid("handshake")
	}
	return config, nil
}

func parseRestlsPlugin(values *pluginValues) (restls.Config, error) {
	config := restls.Config{}
	var err error
	if config.Password, err = values.string("password", "", true); err != nil {
		return config, err
	}
	if config.Script, err = values.string("restls-script", "", false, "restls_script"); err != nil {
		return config, err
	}
	if config.Handshake, err = values.string("dest", "", true, "handshake"); err != nil {
		return config, err
	}
	if !validAddress(config.Handshake) {
		return config, values.invalid("dest")
	}
	if config.MinRecordLen, err = values.integer("min-record-len", 0, "min_record_len"); err != nil ||
		config.MinRecordLen < 0 {
		return config, values.invalid("min-record-len")
	}
	return config, nil
}

func validAddress(address string) bool {
	host, port, err := net.SplitHostPort(address)
	if err != nil || strings.TrimSpace(host) == "" {
		return false
	}
	parsed, err := strconv.ParseUint(port, 10, 16)
	return err == nil && parsed > 0
}
