// SPDX-License-Identifier: GPL-3.0-or-later
// Adapted from Polaris; see THIRD_PARTY_NOTICES.md.
package plugin

import (
	"context"
	"net"

	M "github.com/sagernet/sing/common/metadata"

	"github.com/Ember-Moth/Lunaris/internal/transport/ssplugin/gost"
	"github.com/Ember-Moth/Lunaris/internal/transport/ssplugin/obfs"
	"github.com/Ember-Moth/Lunaris/internal/transport/ssplugin/restls"
	"github.com/Ember-Moth/Lunaris/internal/transport/ssplugin/shadowtls"
	"github.com/Ember-Moth/Lunaris/internal/transport/ssplugin/v2ray"
)

// ConnectionService receives the streams a plugin unwraps.
type ConnectionService interface {
	NewConnection(context.Context, net.Conn, M.Metadata) error
}

// ErrorHandler reports plugin stream failures that do not belong to one
// connection.
type ErrorHandler func(context.Context, error)

type obfsService struct {
	config     obfs.Config
	downstream ConnectionService
}

func (service *obfsService) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	return service.downstream.NewConnection(ctx, obfs.Wrap(service.config, conn), metadata)
}

// NewService wraps the downstream service with the configured plugin, or returns
// it unchanged when no plugin is configured.
func NewService(config *Config, downstream ConnectionService, onError ErrorHandler) (ConnectionService, error) {
	if config == nil {
		return downstream, nil
	}
	switch config.Name {
	case NameObfs:
		return &obfsService{config: config.Obfs, downstream: downstream}, nil
	case NameV2Ray:
		return v2ray.NewService(config.V2Ray, downstream, v2ray.ErrorHandler(onError)), nil
	case NameGost:
		return gost.NewService(config.Gost, downstream, gost.ErrorHandler(onError)), nil
	case NameShadowTLS:
		return shadowtls.NewService(config.ShadowTLS, downstream)
	case NameRestls:
		return restls.NewService(config.Restls, downstream)
	case NameKcptun:
		return downstream, nil
	default:
		return nil, &Error{Plugin: config.Name, Cause: ErrUnsupported}
	}
}
