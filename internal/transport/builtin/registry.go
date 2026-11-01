// SPDX-License-Identifier: GPL-3.0-only
package builtin

import "github.com/Ember-Moth/Lunaris/internal/transport"

func NewRegistry() (*transport.Registry, error) {
	return transport.NewRegistry(transport.NativeFactory{}, transport.TCPFactory{}, transport.WebSocketFactory{}, transport.HTTPUpgradeFactory{}, transport.QUICFactory{}, transport.RealityFactory{}, transport.HTTPFactory{}, transport.XHTTPFactory{})
}
