// SPDX-License-Identifier: GPL-3.0-only
package admin

import (
	"context"
	"github.com/Ember-Moth/Lunaris/internal/outbound"
	"github.com/Ember-Moth/Lunaris/internal/protocol/shadowsocks"
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
)

func (a *API) systemVersion(_ context.Context, c *app.RequestContext) {
	reply(c, 200, 0, "ok", a.version)
}
func (a *API) capabilities(_ context.Context, c *app.RequestContext) {
	methods := append(append([]string{}, shadowsocks.Methods...), shadowaead_2022.List...)
	reply(c, 200, 0, "ok", map[string]any{"schema_version": 1, "protocols": a.registry.Protocols().Capabilities(), "transports": a.registry.Transports().Capabilities(), "shadowsocks_methods": methods, "vless_flows": []string{"", "xtls-rprx-vision"}, "snell_versions": []int{5, 6}, "credential_kinds": credentialKinds, "connection_info_format": "parameters-v1", "outbound_protocols": outbound.NewRegistry().Capabilities(), "route_actions": []string{"direct", "block", "route"}, "route_selectors": []string{"full", "suffix", "keyword", "regex", "cidr", "geosite", "geoip"}, "dns_protocols": []string{"udp", "tcp", "tls", "https"}, "dns_strategies": []string{"prefer_ipv4", "prefer_ipv6", "only_ipv4", "only_ipv6"}, "geodata_kinds": []string{"geosite", "geoip"}})
}
func (a *API) status(ctx context.Context, c *app.RequestContext) {
	status, err := a.service.Status(ctx)
	if err != nil {
		a.error(c, err, false)
		return
	}
	reply(c, 200, 0, "ok", status)
}
func (a *API) logPage(_ context.Context, c *app.RequestContext) {
	cursor, limit, ok := a.pagination(c)
	if !ok {
		return
	}
	page, err := a.logs.Page(cursor, limit)
	if err != nil {
		a.fail(c, 400, 40000, "Invalid log cursor", nil)
		return
	}
	reply(c, 200, 0, "ok", page)
}
