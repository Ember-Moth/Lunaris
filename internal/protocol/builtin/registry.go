// SPDX-License-Identifier: GPL-3.0-only
package builtin

import (
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/Ember-Moth/Lunaris/internal/protocol/quic"
	"github.com/Ember-Moth/Lunaris/internal/protocol/shadowsocks"
	"github.com/Ember-Moth/Lunaris/internal/protocol/stream"
)

func NewRegistry() (*protocol.Registry, error) {
	return protocol.NewRegistry(shadowsocks.Factory{}, stream.Factory{Type: "vless"}, stream.Factory{Type: "vmess"}, stream.Factory{Type: "trojan"}, stream.Factory{Type: "anytls"}, quic.Factory{Type: "hysteria2"}, quic.Factory{Type: "tuic"})
}
