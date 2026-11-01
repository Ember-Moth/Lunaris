// SPDX-License-Identifier: GPL-3.0-or-later
// Adapted from Polaris; see THIRD_PARTY_NOTICES.md.
package plugin

import (
	"strings"

	"github.com/Ember-Moth/Lunaris/internal/transport/ssplugin/kcptun"
)

func parseKcptunPlugin(values *pluginValues) (kcptun.Config, error) {
	config := kcptun.Config{}
	var err error
	if config.Key, err = values.string("key", "", true); err != nil {
		return config, err
	}
	if config.Crypt, err = values.string("crypt", "aes", false); err != nil {
		return config, err
	}
	config.Crypt = strings.ToLower(strings.TrimSpace(config.Crypt))
	if !validKcptunCrypt(config.Crypt) {
		return config, values.invalid("crypt")
	}
	if config.Mode, err = values.string("mode", "fast", false); err != nil {
		return config, err
	}
	config.Mode = strings.ToLower(strings.TrimSpace(config.Mode))
	integers := []struct {
		field    string
		fallback int
		target   *int
	}{
		{"conn", 1, &config.Conn},
		{"autoexpire", 0, &config.AutoExpire},
		{"scavengettl", 600, &config.ScavengeTTL},
		{"mtu", 1350, &config.MTU},
		{"ratelimit", 0, &config.RateLimit},
		{"sndwnd", 128, &config.SndWnd},
		{"rcvwnd", 512, &config.RcvWnd},
		{"datashard", 10, &config.DataShard},
		{"parityshard", 3, &config.ParityShard},
		{"dscp", 0, &config.DSCP},
		{"nodelay", 0, &config.NoDelay},
		{"interval", 50, &config.Interval},
		{"resend", 0, &config.Resend},
		{"nc", 0, &config.NoCongestion},
		{"sockbuf", 4194304, &config.SockBuf},
		{"smuxver", 1, &config.SmuxVer},
		{"smuxbuf", 4194304, &config.SmuxBuf},
		{"framesize", 8192, &config.FrameSize},
		{"streambuf", 2097152, &config.StreamBuf},
		{"keepalive", 10, &config.KeepAlive},
	}
	for _, item := range integers {
		*item.target, err = values.integer(item.field, item.fallback)
		if err != nil || *item.target < 0 {
			return config, values.invalid(item.field)
		}
	}
	if config.NoComp, err = values.boolean("nocomp", false); err != nil {
		return config, err
	}
	if config.AckNodelay, err = values.boolean("acknodelay", false); err != nil {
		return config, err
	}
	if config.AllowInsecure, err = values.boolean("allow-insecure", false, "allow_insecure"); err != nil {
		return config, err
	}
	if insecureKcptunCrypt(config.Crypt) && !config.AllowInsecure {
		return config, values.invalid("crypt")
	}
	if config.MaxSessions, err = parsePluginLimit(values, "max-sessions", 1<<20, "max_sessions"); err != nil {
		return config, err
	}
	if config.MaxStreams, err = parsePluginLimit(values, "max-streams", 65535, "max_streams"); err != nil {
		return config, err
	}
	if config.MaxActiveStreams, err = parsePluginLimit(values, "max-active-streams", 1<<20,
		"max_active_streams"); err != nil {
		return config, err
	}
	if config.Conn < 1 || config.MTU < 576 || config.SndWnd < 1 || config.RcvWnd < 1 ||
		config.DataShard < 1 || config.DSCP > 63 || config.SockBuf < 1 ||
		config.SmuxVer < 1 || config.SmuxVer > 2 || config.SmuxBuf < 1 ||
		config.FrameSize < 1 || config.FrameSize > 65535 || config.StreamBuf < 1 || config.KeepAlive < 1 {
		return config, values.invalid("kcptun")
	}
	if !applyKcptunMode(&config) {
		return config, values.invalid("mode")
	}
	return config, nil
}

func insecureKcptunCrypt(crypt string) bool {
	switch crypt {
	case "null", "none", "xor", "tea", "3des":
		return true
	default:
		return false
	}
}

func validKcptunCrypt(crypt string) bool {
	switch crypt {
	case "null", "tea", "xor", "none", "aes-128", "aes-192", "blowfish", "twofish",
		"cast5", "3des", "xtea", "salsa20", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "aes":
		return true
	default:
		return false
	}
}

func applyKcptunMode(config *kcptun.Config) bool {
	switch config.Mode {
	case "normal":
		config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 0, 40, 2, 1
	case "fast":
		config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 0, 30, 2, 1
	case "fast2":
		config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 1, 20, 2, 1
	case "fast3":
		config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 1, 10, 2, 1
	case "manual":
	default:
		return false
	}
	return true
}
