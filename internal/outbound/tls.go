// SPDX-License-Identifier: GPL-3.0-only
package outbound

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

type TLSOptions struct {
	Enabled    bool     `json:"enabled,omitempty"`
	ServerName string   `json:"server_name,omitempty"`
	ALPN       []string `json:"alpn,omitempty"`
	CAPEM      string   `json:"ca_pem,omitempty"`
	Insecure   bool     `json:"insecure,omitempty"`
}

func normalizeTLS(options *TLSOptions, server string, required, quic bool) (*TLSOptions, error) {
	if options == nil {
		if !required {
			return nil, nil
		}
		options = &TLSOptions{Enabled: true}
	}
	copy := *options
	copy.ALPN = slices.Clone(options.ALPN)
	if !copy.Enabled {
		if required || copy.ServerName != "" || len(copy.ALPN) > 0 || copy.CAPEM != "" || copy.Insecure {
			return nil, errors.New("TLS is required or disabled TLS has active options")
		}
		return nil, nil
	}
	if copy.ServerName == "" {
		copy.ServerName = server
	}
	if len(copy.ServerName) > 253 || strings.ContainsAny(copy.ServerName, " /\\\x00\r\n\t") || len(copy.ALPN) > 8 || len(copy.CAPEM) > 16384 {
		return nil, errors.New("invalid outbound TLS options")
	}
	for _, protocol := range copy.ALPN {
		if len(protocol) == 0 || len(protocol) > 255 || strings.ContainsAny(protocol, "\x00\r\n") {
			return nil, errors.New("invalid TLS ALPN")
		}
	}
	if quic && len(copy.ALPN) == 0 {
		copy.ALPN = []string{"h3"}
	}
	if copy.Insecure && copy.CAPEM != "" {
		return nil, errors.New("insecure TLS cannot specify trust roots")
	}
	if _, err := copy.config(quic); err != nil {
		return nil, err
	}
	return &copy, nil
}
func (o *TLSOptions) config(quic bool) (*tls.Config, error) {
	if o == nil {
		return nil, nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: o.ServerName, NextProtos: slices.Clone(o.ALPN), InsecureSkipVerify: o.Insecure}
	if quic {
		cfg.MinVersion = tls.VersionTLS13
	}
	if o.CAPEM != "" {
		cfg.RootCAs = x509.NewCertPool()
		remaining := []byte(o.CAPEM)
		count := 0
		for len(strings.TrimSpace(string(remaining))) > 0 {
			block, rest := pem.Decode(remaining)
			if block == nil || block.Type != "CERTIFICATE" {
				return nil, errors.New("ca_pem must contain only certificates")
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, errors.New("invalid TLS trust certificate")
			}
			cfg.RootCAs.AddCert(cert)
			remaining = rest
			count++
		}
		if count == 0 {
			return nil, errors.New("empty TLS trust roots")
		}
	}
	return cfg, nil
}

type streamCarrier struct {
	dialer  N.Dialer
	server  M.Socksaddr
	tls     *tls.Config
	timeout time.Duration
}

func newCarrier(spec model.OutboundSpec, options *TLSOptions, dialer N.Dialer, limits model.Limits) (*streamCarrier, error) {
	cfg, err := options.config(false)
	if err != nil {
		return nil, err
	}
	return &streamCarrier{dialer: dialer, server: M.ParseSocksaddrHostPort(spec.Address, spec.Port), tls: cfg, timeout: limits.HandshakeTimeout}, nil
}
func (c *streamCarrier) open(ctx context.Context) (net.Conn, error) {
	raw, err := c.dialer.DialContext(ctx, "tcp", c.server)
	if err != nil {
		return nil, err
	}
	if c.tls == nil {
		return raw, nil
	}
	secure := tls.Client(raw, c.tls)
	if err = handshake(ctx, raw, func() error { return secure.HandshakeContext(ctx) }); err != nil {
		return nil, err
	}
	if err = secure.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		secure.Close()
		return nil, err
	}
	return secure, nil
}

type clientTLSConfig struct {
	config  *tls.Config
	timeout time.Duration
}

func (c *clientTLSConfig) ServerName() string                  { return c.config.ServerName }
func (c *clientTLSConfig) SetServerName(v string)              { c.config.ServerName = v }
func (c *clientTLSConfig) NextProtos() []string                { return slices.Clone(c.config.NextProtos) }
func (c *clientTLSConfig) SetNextProtos(v []string)            { c.config.NextProtos = slices.Clone(v) }
func (c *clientTLSConfig) HandshakeTimeout() time.Duration     { return c.timeout }
func (c *clientTLSConfig) SetHandshakeTimeout(v time.Duration) { c.timeout = v }
func (c *clientTLSConfig) STDConfig() (*tls.Config, error)     { return c.config.Clone(), nil }
func (c *clientTLSConfig) Client(conn net.Conn) (aTLS.Conn, error) {
	return tls.Client(conn, c.config.Clone()), nil
}
func (c *clientTLSConfig) Clone() aTLS.Config {
	return &clientTLSConfig{config: c.config.Clone(), timeout: c.timeout}
}
