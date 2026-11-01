// SPDX-License-Identifier: GPL-3.0-or-later
// Adapted from Polaris; see THIRD_PARTY_NOTICES.md.
package plugin

import (
	"strings"

	"github.com/Ember-Moth/Lunaris/internal/transport/ssplugin/obfs"
)

func parseObfsPlugin(values *pluginValues) (obfs.Config, error) {
	mode, err := values.string("mode", "", true, "obfs")
	if err != nil {
		return obfs.Config{}, err
	}
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != "http" && mode != "tls" {
		return obfs.Config{}, values.invalid("mode")
	}
	return obfs.Config{Mode: mode}, nil
}
