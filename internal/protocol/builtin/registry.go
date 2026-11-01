// SPDX-License-Identifier: GPL-3.0-only
package builtin

import (
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/Ember-Moth/Lunaris/internal/protocol/shadowsocks"
)

func NewRegistry() (*protocol.Registry, error) {
	return protocol.NewRegistry(shadowsocks.Factory{})
}
