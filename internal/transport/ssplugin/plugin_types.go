// SPDX-License-Identifier: GPL-3.0-or-later
// Adapted from Polaris; see THIRD_PARTY_NOTICES.md.
package plugin

import (
	"errors"

	"github.com/Ember-Moth/Lunaris/internal/transport/ssplugin/gost"
	"github.com/Ember-Moth/Lunaris/internal/transport/ssplugin/kcptun"
	"github.com/Ember-Moth/Lunaris/internal/transport/ssplugin/obfs"
	"github.com/Ember-Moth/Lunaris/internal/transport/ssplugin/restls"
	"github.com/Ember-Moth/Lunaris/internal/transport/ssplugin/shadowtls"
	"github.com/Ember-Moth/Lunaris/internal/transport/ssplugin/v2ray"
)

// Errors reported while validating the panel's plugin options.
var (
	ErrUnsupported   = errors.New("shadowsocks: unsupported inbound plugin")
	ErrInvalidOption = errors.New("shadowsocks: invalid plugin option")
)

// Name identifies one supported inbound plugin.
type Name string

// Inbound plugin names accepted from the panel configuration.
const (
	NameObfs      Name = "obfs"
	NameV2Ray     Name = "v2ray-plugin"
	NameGost      Name = "gost-plugin"
	NameShadowTLS Name = "shadow-tls"
	NameRestls    Name = "restls"
	NameKcptun    Name = "kcptun"
)

// Error names the plugin and option that were rejected and the cause.
type Error struct {
	Plugin Name
	Field  string
	Cause  error
}

func (detail *Error) Error() string {
	prefix := "shadowsocks: plugin"
	if detail.Plugin != "" {
		prefix += " " + string(detail.Plugin)
	}
	if detail.Field != "" {
		prefix += " option " + detail.Field
	}
	return prefix + ": " + detail.Cause.Error()
}

func (detail *Error) Unwrap() error { return detail.Cause }

// Config is the validated plugin selection with the configuration of the
// selected plugin.
type Config struct {
	Name      Name
	Obfs      obfs.Config
	V2Ray     v2ray.Config
	Gost      gost.Config
	ShadowTLS shadowtls.Config
	Restls    restls.Config
	Kcptun    kcptun.Config
}

// UsesMultiplex reports whether the plugin places Shadowsocks streams inside
// its own multiplexing layer. Kcptun always uses smux for its stream carrier.
func UsesMultiplex(config *Config) bool {
	if config == nil {
		return false
	}
	switch config.Name {
	case NameV2Ray:
		return config.V2Ray.Mux
	case NameGost:
		return config.Gost.Mux
	case NameKcptun:
		return true
	default:
		return false
	}
}

// KcptunServer is the kcptun session server the Shadowsocks listener drives
// directly.
type KcptunServer = kcptun.Server

// NewKcptunServer constructs the kcptun session server from its validated
// configuration.
var NewKcptunServer = kcptun.NewServer
