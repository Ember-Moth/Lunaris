// SPDX-License-Identifier: GPL-3.0-only
package transport

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
	legacy "github.com/metacubex/utls"
	N "github.com/sagernet/sing/common/network"
	reality "github.com/xtls/reality"
)

type RealityFactory struct{}

func (RealityFactory) Capabilities() Capabilities {
	return Capabilities{Type: "reality", TCP: true, Secure: true}
}
func (RealityFactory) Validate(s model.ListenerSpec) []model.FieldError {
	if len(s.Transport.Plugin) > 0 {
		return field("transport.plugin", "plugin settings require a plugin transport")
	}
	if s.Transport.XHTTP != nil {
		return field("transport.xhttp", "XHTTP settings require the xhttp transport")
	}
	r := s.Transport.Reality
	if r == nil {
		return field("transport.reality", "REALITY settings are required")
	}
	if s.CertificateRef != "" || s.Transport.Path != "" || s.Transport.Host != "" {
		return field("transport", "REALITY uses its key and target, without certificate_ref, path or host")
	}
	host, port, err := net.SplitHostPort(r.Target)
	n, e := strconv.Atoi(port)
	if err != nil || e != nil || host == "" || n < 1 || n > 65535 || strings.ContainsAny(host, "\r\n\t /\\") {
		return field("transport.reality.target", "target must be host:port")
	}
	if r.PrivateKeyRef == "" {
		return field("transport.reality.private_key_ref", "private key reference is required")
	}
	if len(r.ServerNames) == 0 || len(r.ServerNames) > 8 {
		return field("transport.reality.server_names", "set 1 to 8 server names")
	}
	names := map[string]bool{}
	for _, name := range r.ServerNames {
		if name == "" || len(name) > 253 || name != strings.ToLower(name) || strings.ContainsAny(name, "\r\n\t /\\:*[]") || names[name] {
			return field("transport.reality.server_names", "server names must be unique lowercase hostnames")
		}
		names[name] = true
	}
	if len(r.ShortIDs) == 0 || len(r.ShortIDs) > 64 {
		return field("transport.reality.short_ids", "set 1 to 64 short IDs")
	}
	ids := map[[8]byte]bool{}
	for _, raw := range r.ShortIDs {
		b, err := hex.DecodeString(raw)
		if err != nil || len(b) > 8 {
			return field("transport.reality.short_ids", "short IDs must be even-length hex strings up to 16 characters")
		}
		var id [8]byte
		copy(id[:], b)
		if ids[id] {
			return field("transport.reality.short_ids", "duplicate short ID")
		}
		ids[id] = true
	}
	if r.MaxTimeDifference < 0 || r.MaxTimeDifference > 24*time.Hour {
		return field("transport.reality.max_time_difference", "time difference must be between zero and 24h")
	}
	return nil
}
func (RealityFactory) CredentialRefs(s model.ListenerSpec) []string {
	if s.Transport.Reality == nil {
		return nil
	}
	return []string{s.Transport.Reality.PrivateKeyRef}
}
func decodeRealityKey(r ResolvedSpec) (*ecdh.PrivateKey, error) {
	if r.Transport.Reality == nil {
		return nil, errors.New("REALITY settings required")
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(string(r.Secrets[r.Transport.Reality.PrivateKeyRef]))
	if err != nil || len(b) != 32 {
		return nil, errors.New("REALITY private key must be a base64url-encoded 32-byte X25519 key")
	}
	key, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		return nil, errors.New("invalid REALITY private key")
	}
	return key, nil
}
func (RealityFactory) ValidateAssets(r ResolvedSpec) error { _, err := decodeRealityKey(r); return err }
func (RealityFactory) Build(r ResolvedSpec, b Binding) (Instance, error) {
	key, err := decodeRealityKey(r)
	if err != nil {
		return nil, err
	}
	if len(r.Certificate) > 0 || len(r.PrivateKey) > 0 {
		return nil, errors.New("REALITY does not use a TLS certificate")
	}
	s, err := newSocketServer(r, b, nil)
	if err != nil {
		return nil, err
	}
	options := r.Transport.Clone().Reality
	cfg := &reality.Config{SessionTicketsDisabled: true, Type: "tcp", Dest: options.Target, PrivateKey: key, ServerNames: make(map[string]bool), ShortIds: make(map[[8]byte]bool), MaxTimeDiff: options.MaxTimeDifference}
	if cfg.MaxTimeDiff == 0 {
		cfg.MaxTimeDiff = time.Minute
	}
	for _, name := range options.ServerNames {
		cfg.ServerNames[name] = true
	}
	for _, raw := range options.ShortIDs {
		b, _ := hex.DecodeString(raw)
		var id [8]byte
		copy(id[:], b)
		cfg.ShortIds[id] = true
	}
	var leases []string
	s.prepare = func(ctx context.Context) error {
		probeCtx, cancel := context.WithTimeout(ctx, r.Limits.DialTimeout+r.Limits.HandshakeTimeout)
		defer cancel()
		var err error
		leases, err = acquireRealityRecords(probeCtx, cfg, r.Limits.DialTimeout)
		return err
	}
	s.cleanup = func() { releaseRealityRecords(leases) }
	s.handshake = func(ctx context.Context, c net.Conn) (net.Conn, error) {
		carrier := ctx.Value(carrierKey{}).(*trackedConn)
		handshake, cancel := context.WithDeadline(ctx, carrier.deadline)
		defer cancel()
		perConnection := cfg.Clone()
		perConnection.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			raw, err := (&net.Dialer{Timeout: r.Limits.DialTimeout}).DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			if deadline, ok := ctx.Deadline(); ok {
				_ = raw.SetDeadline(deadline)
			}
			conn := &contextConn{Conn: raw}
			conn.stop = context.AfterFunc(ctx, func() { raw.Close() })
			return conn, nil
		}
		if options.AllowLegacyClients {
			selected, compat, err := selectRealityBackend(c)
			if err != nil {
				return nil, errors.New("invalid or incomplete REALITY ClientHello")
			}
			c = selected
			if compat {
				compatible := &legacy.RealityConfig{DialContext: perConnection.DialContext, Type: "tcp", Dest: cfg.Dest, ServerNames: cfg.ServerNames, PrivateKey: key.Bytes(), MaxTimeDiff: cfg.MaxTimeDiff, ShortIds: cfg.ShortIds, Config: legacy.Config{SessionTicketsDisabled: true}}
				conn, err := legacy.RealityServer(handshake, c, compatible)
				if err != nil {
					return nil, errors.New("compatible REALITY handshake or fallback finished")
				}
				return &legacyRealityConn{Conn: conn}, nil
			}
		}
		conn, err := reality.Server(handshake, c, perConnection)
		if err != nil {
			return nil, errors.New("REALITY handshake or fallback finished")
		}
		return conn, nil
	}
	return s, nil
}

// The upstream server owns the fallback exchange; its target connection is also
// tied to our bounded handshake context, including target-side blocked reads.
type contextConn struct {
	net.Conn
	stop func() bool
	once sync.Once
}

func (c *contextConn) Close() error {
	var err error
	c.once.Do(func() { c.stop(); err = c.Conn.Close() })
	return err
}
func (c *contextConn) CloseWrite() error { return N.CloseWrite(c.Conn) }
