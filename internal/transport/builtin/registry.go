// SPDX-License-Identifier: GPL-3.0-only
package builtin

import "github.com/Ember-Moth/Lunaris/internal/transport"

func NewRegistry() (*transport.Registry, error) {
	return transport.NewRegistry(transport.NativeFactory{}, transport.TCPFactory{}, transport.WebSocketFactory{}, transport.HTTPUpgradeFactory{}, transport.QUICFactory{}, transport.RealityFactory{}, transport.HTTPFactory{}, transport.XHTTPFactory{}, transport.PluginFactory{Kind: "obfs"}, transport.PluginFactory{Kind: "v2ray-plugin"}, transport.PluginFactory{Kind: "gost-plugin"}, transport.PluginFactory{Kind: "shadow-tls"}, transport.PluginFactory{Kind: "restls"}, transport.PluginFactory{Kind: "kcptun"})
}
