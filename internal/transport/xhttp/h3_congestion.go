// SPDX-License-Identifier: GPL-3.0-or-later

package xhttp

import (
	"github.com/sagernet/quic-go"
	congestionMeta2 "github.com/sagernet/sing-quic/congestion_meta2"
)

const (
	h3InitialStreamReceiveWindow     = 512 << 10
	h3MaxStreamReceiveWindow         = 4 << 20
	h3InitialConnectionReceiveWindow = 1 << 20
	h3MaxConnectionReceiveWindow     = 16 << 20
)

func enableH3BBR(conn *quic.Conn) {
	packetSize := conn.InitialPacketSize()
	conn.SetCongestionControl(congestionMeta2.NewBbrSenderWithProfile(
		packetSize,
		congestionMeta2.ProfileStandard,
	))
}

func h3QUICConfig(config Config, server bool) *quic.Config {
	quicConfig := &quic.Config{
		MaxIdleTimeout:                 connectionIdleTimeout,
		KeepAlivePeriod:                h3KeepaliveDuration(config.XMUX.HKeepAlivePeriod),
		InitialStreamReceiveWindow:     uint64(config.H3InitialStreamReceiveWindow),
		MaxStreamReceiveWindow:         uint64(config.H3MaxStreamReceiveWindow),
		InitialConnectionReceiveWindow: uint64(config.H3InitialConnectionReceiveWindow),
		MaxConnectionReceiveWindow:     uint64(config.H3MaxConnectionReceiveWindow),
	}
	if server {
		quicConfig.MaxIncomingStreams = 1024
	} else {
		quicConfig.MaxIncomingStreams = -1
	}
	return quicConfig
}

// ServerQUICConfig supplies wire settings to a host-owned QUIC listener.
func (config Config) ServerQUICConfig() *quic.Config { return h3QUICConfig(config, true) }

// ConfigureQUICConnection applies the migrated Polaris BBR policy.
func ConfigureQUICConnection(conn *quic.Conn) { enableH3BBR(conn) }
