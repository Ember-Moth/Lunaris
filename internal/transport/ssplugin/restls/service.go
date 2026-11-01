// SPDX-License-Identifier: GPL-3.0-or-later
// Adapted from Polaris; see THIRD_PARTY_NOTICES.md.
package restls

import (
	"context"
	"net"

	protocol "github.com/Ember-Moth/Lunaris/internal/transport/ssplugin/restls/wire"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Config is the validated Restls configuration.
type Config struct {
	Dialer       N.Dialer
	Handshake    string
	Password     string
	Script       string
	MinRecordLen int
}

// ConnectionService receives the streams the plugin unwraps.
type ConnectionService interface {
	NewConnection(context.Context, net.Conn, M.Metadata) error
}

// Service terminates Restls handshakes in front of the Shadowsocks service.
type Service struct {
	server     *protocol.Server
	downstream ConnectionService
}

// NewService builds the Restls server from its configuration.
func NewService(config Config, downstream ConnectionService) (*Service, error) {
	server, err := protocol.NewServer(protocol.ServerConfig{
		Handshake:    M.ParseSocksaddr(config.Handshake),
		Password:     config.Password,
		Script:       config.Script,
		MinRecordLen: config.MinRecordLen,
		Dialer:       config.Dialer,
	})
	if err != nil {
		return nil, err
	}
	return &Service{server: server, downstream: downstream}, nil
}

// NewConnection completes the Restls handshake and passes the inner stream
// downstream.
func (service *Service) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	wrapped, err := service.server.NewConnection(ctx, conn)
	if err != nil {
		return err
	}
	return service.downstream.NewConnection(ctx, wrapped, metadata)
}
