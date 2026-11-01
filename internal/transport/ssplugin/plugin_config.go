// SPDX-License-Identifier: GPL-3.0-or-later
// Adapted from Polaris; see THIRD_PARTY_NOTICES.md.
package plugin

import (
	"strings"

	"maps"
)

// Parse validates one built-in Shadowsocks inbound plugin configuration.
func Parse(rawName string, options map[string]any) (*Config, error) {
	name := normalizeName(rawName)
	if name == "" {
		if len(options) == 0 {
			return nil, nil
		}
		return nil, &Error{Field: "plugin", Cause: ErrInvalidOption}
	}
	values := newPluginValues(name, maps.Clone(options))
	config := Config{Name: name}
	var err error
	switch name {
	case NameObfs:
		config.Obfs, err = parseObfsPlugin(values)
	case NameV2Ray:
		config.V2Ray, err = parseV2RayPlugin(values)
	case NameGost:
		config.Gost, err = parseGostPlugin(values)
	case NameShadowTLS:
		config.ShadowTLS, err = parseShadowTLSPlugin(values)
	case NameRestls:
		config.Restls, err = parseRestlsPlugin(values)
	case NameKcptun:
		config.Kcptun, err = parseKcptunPlugin(values)
	default:
		return nil, &Error{Plugin: name, Cause: ErrUnsupported}
	}
	if err != nil {
		return nil, err
	}
	if err := values.finish(); err != nil {
		return nil, err
	}
	return &config, nil
}

func normalizeName(raw string) Name {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return ""
	case "obfs", "obfs-local", "obfs-server", "simple-obfs":
		return NameObfs
	case "v2ray-plugin":
		return NameV2Ray
	case "gost-plugin":
		return NameGost
	case "shadow-tls", "shadowtls":
		return NameShadowTLS
	case "restls", "res-tls":
		return NameRestls
	case "kcptun", "kcp-tun":
		return NameKcptun
	default:
		return Name(strings.ToLower(strings.TrimSpace(raw)))
	}
}
