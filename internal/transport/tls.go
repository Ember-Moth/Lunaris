// SPDX-License-Identifier: GPL-3.0-only
package transport

import (
	"crypto/tls"
	aTLS "github.com/sagernet/sing/common/tls"
	"net"
	"time"
)

// TLS bridges Go's TLS implementation to sing's configuration contract.
type TLS struct {
	Config  *tls.Config
	Timeout time.Duration
}

func (t *TLS) ServerName() string                   { return t.Config.ServerName }
func (t *TLS) SetServerName(s string)               { t.Config.ServerName = s }
func (t *TLS) NextProtos() []string                 { return t.Config.NextProtos }
func (t *TLS) SetNextProtos(p []string)             { t.Config.NextProtos = p }
func (t *TLS) HandshakeTimeout() time.Duration      { return t.Timeout }
func (t *TLS) SetHandshakeTimeout(d time.Duration)  { t.Timeout = d }
func (t *TLS) STDConfig() (*tls.Config, error)      { return t.Config, nil }
func (t *TLS) Client(c net.Conn) (aTLS.Conn, error) { return tls.Client(c, t.Config), nil }
func (t *TLS) Server(c net.Conn) (aTLS.Conn, error) { return tls.Server(c, t.Config), nil }
func (t *TLS) Clone() aTLS.Config                   { return &TLS{Config: t.Config.Clone(), Timeout: t.Timeout} }
func (*TLS) Start() error                           { return nil }
func (*TLS) Close() error                           { return nil }
