// SPDX-License-Identifier: GPL-3.0-only
package builtin

import (
	"github.com/Ember-Moth/Lunaris/internal/inbound"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/Ember-Moth/Lunaris/internal/protocol/anytls"
	"github.com/Ember-Moth/Lunaris/internal/protocol/hysteria2"
	"github.com/Ember-Moth/Lunaris/internal/protocol/shadowsocks"
	"github.com/Ember-Moth/Lunaris/internal/protocol/trojan"
	"github.com/Ember-Moth/Lunaris/internal/protocol/tuic"
	"github.com/Ember-Moth/Lunaris/internal/protocol/vless"
	"github.com/Ember-Moth/Lunaris/internal/protocol/vmess"
	transportbuiltin "github.com/Ember-Moth/Lunaris/internal/transport/builtin"
)

func NewProtocols() (*protocol.Registry, error) {
	return protocol.NewRegistry(shadowsocks.Factory{}, vless.Factory{}, vmess.Factory{}, trojan.Factory{}, anytls.Factory{}, hysteria2.Factory{}, tuic.Factory{})
}
func NewRegistry() (*inbound.Registry, error) {
	p, err := NewProtocols()
	if err != nil {
		return nil, err
	}
	t, err := transportbuiltin.NewRegistry()
	if err != nil {
		return nil, err
	}
	return inbound.NewRegistry(p, t)
}
