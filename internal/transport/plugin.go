// SPDX-License-Identifier: GPL-3.0-only
package transport

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
	P "github.com/Ember-Moth/Lunaris/internal/transport/ssplugin"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func (f PluginFactory) Build(r ResolvedSpec, b Binding) (Instance, error) {
	if err := model.ValidateLimits(r.Limits); err != nil {
		return nil, err
	}
	if b.Stream == nil || b.Stream.Serve == nil {
		return nil, errors.New("plugin requires a stream protocol")
	}
	spec := model.ListenerSpec{Transport: r.Transport}
	if len(r.Certificate) > 0 {
		spec.CertificateRef = "resolved"
	}
	if fields := f.Validate(spec); len(fields) > 0 {
		return nil, errors.New(fields[0].Message)
	}
	cfg, _, err := parsePlugin(f.Kind, spec, r.Secrets, true)
	if err != nil {
		return nil, err
	}
	limit := r.Limits.MaxConnections + r.Limits.MaxUDPSessions
	bounded := func(value, maximum int) int {
		if value <= 0 {
			return maximum
		}
		return min(value, maximum)
	}
	cfg.V2Ray.MaxActiveStreams = bounded(cfg.V2Ray.MaxActiveStreams, limit)
	cfg.V2Ray.MaxSessions = bounded(cfg.V2Ray.MaxSessions, min(128, limit))
	cfg.V2Ray.HandshakeTimeout = r.Limits.HandshakeTimeout
	cfg.Gost.MaxActiveStreams = bounded(cfg.Gost.MaxActiveStreams, limit)
	cfg.Gost.MaxStreams = bounded(cfg.Gost.MaxStreams, min(128, limit))
	cfg.Gost.HandshakeTimeout = r.Limits.HandshakeTimeout
	cfg.Kcptun.MaxActiveStreams = bounded(cfg.Kcptun.MaxActiveStreams, limit)
	cfg.Kcptun.MaxStreams = bounded(cfg.Kcptun.MaxStreams, min(128, limit))
	cfg.Kcptun.MaxSessions = bounded(cfg.Kcptun.MaxSessions, r.Limits.MaxConnections)
	cfg.Kcptun.MaxPendingSessions = r.Limits.MaxPendingHandshakes
	cfg.Kcptun.HandshakeTimeout = r.Limits.HandshakeTimeout
	cfg.ShadowTLS.Dialer = pluginDialer{timeout: r.Limits.DialTimeout}
	cfg.Restls.Dialer = pluginDialer{timeout: r.Limits.DialTimeout}
	downstream := &pluginDownstream{serve: b.Stream.Serve, limits: r.Limits}
	service, err := P.NewService(cfg, downstream, nil)
	if err != nil {
		return nil, err
	}
	stream := *b.Stream
	stream.Serve = func(ctx context.Context, c net.Conn, src M.Socksaddr, close N.CloseHandlerFunc) error {
		deadline := time.Now().Add(r.Limits.HandshakeTimeout)
		if tracked, ok := ctx.Value(carrierKey{}).(*trackedConn); ok {
			deadline = tracked.deadline
		}
		// Some mux protocols must clear the shared socket deadline. Keep the
		// physical admission timer until the first actual Shadowsocks authentication.
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		stop := context.AfterFunc(ctx, func() { c.Close() })
		defer stop()
		timer := time.AfterFunc(time.Until(deadline), func() { cancel(); c.Close() })
		defer timer.Stop()
		ctx = context.WithValue(ctx, pluginCarrierReadyKey{}, func() { timer.Stop() })
		if cfg.Name == P.NameShadowTLS || cfg.Name == P.NameRestls {
			handoff := &pluginHandoff{deadline: deadline}
			defer handoff.close()
			ctx = context.WithValue(ctx, pluginHandoffKey{}, handoff)
		}
		err := service.NewConnection(ctx, c, M.Metadata{Source: src})
		if close != nil {
			close(err)
		}
		return err
	}
	wrapped := Binding{Stream: &stream}
	// Native UDP is a separate listener; plugin transports carry streams only.
	if cfg.Name == P.NameKcptun {
		server, err := P.NewKcptunServer(cfg.Kcptun)
		if err != nil {
			return nil, err
		}
		wrapped.Packet = &PacketHandler{Serve: func(ctx context.Context, c net.PacketConn) error {
			return server.Serve(ctx, c, func(c net.Conn) {
				_ = downstream.NewConnection(ctx, c, M.Metadata{Source: M.SocksaddrFromNet(c.RemoteAddr())})
			})
		}}
		if b.Packet != nil {
			wrapped.Packet.Close = b.Packet.Close
		}
		r.Network = []string{"udp"}
		return newSocketServer(r, wrapped, nil)
	}
	// Preserve protocol-owned cleanup even when its native UDP entry is unused.
	if b.Packet != nil && b.Packet.Close != nil {
		old := stream.Close
		stream.Close = func() error {
			var err error
			if old != nil {
				err = old()
			}
			return errors.Join(err, b.Packet.Close(context.Background()))
		}
	}
	if cfg.Name == P.NameV2Ray || cfg.Name == P.NameGost {
		config := cfg.V2Ray.WebSocket
		if cfg.Name == P.NameGost {
			config = cfg.Gost.WebSocket
		}
		r.Transport.Path = config.Path
		r.Transport.Host = config.Host
		s, err := newSocketServer(r, wrapped, pluginWebsocketUpgrade(config))
		if err != nil {
			return nil, err
		}
		s.httpMaxHeaderBytes += base64.RawURLEncoding.EncodedLen(config.MaxEarlyData)
		return s, nil
	}
	return newSocketServer(r, wrapped, nil)
}

type pluginCarrierReadyKey struct{}
type pluginHandoffKey struct{}
type pluginHandoff struct {
	mu       sync.Mutex
	deadline time.Time
	targets  []net.Conn
	promoted bool
}

// RESTLS retains its target and context for cover traffic after authentication.
// Promote its deadline while retaining connection ownership through shutdown.
func (h *pluginHandoff) promote() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.promoted = true
	for _, c := range h.targets {
		_ = c.SetDeadline(time.Time{})
	}
}
func (h *pluginHandoff) track(c net.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.promoted {
		_ = c.SetDeadline(time.Time{})
	} else {
		_ = c.SetDeadline(h.deadline)
	}
	h.targets = append(h.targets, c)
}
func (h *pluginHandoff) close() {
	h.mu.Lock()
	targets := h.targets
	h.mu.Unlock()
	for _, c := range targets {
		c.Close()
	}
}

type pluginDownstream struct {
	serve           ServeFunc
	limits          model.Limits
	mu              sync.Mutex
	active, pending int
}

func (d *pluginDownstream) NewConnection(ctx context.Context, c net.Conn, metadata M.Metadata) error {
	if handoff, ok := ctx.Value(pluginHandoffKey{}).(*pluginHandoff); ok {
		handoff.promote()
	}
	d.mu.Lock()
	if ctx.Err() != nil || d.active >= d.limits.MaxConnections+d.limits.MaxUDPSessions || d.pending >= d.limits.MaxPendingHandshakes {
		d.mu.Unlock()
		c.Close()
		return errors.New("plugin stream admission limit reached")
	}
	d.active++
	d.pending++
	pending := true
	d.mu.Unlock()
	done := make(chan struct{})
	var closeOnce sync.Once
	finish := func(error) { closeOnce.Do(func() { _ = c.Close(); close(done) }) }
	stop := context.AfterFunc(ctx, func() { finish(ctx.Err()) })
	defer stop()
	timer := time.AfterFunc(d.limits.HandshakeTimeout, func() { finish(context.DeadlineExceeded) })
	defer timer.Stop()
	_ = c.SetDeadline(time.Now().Add(d.limits.HandshakeTimeout))
	defer func() {
		finish(nil)
		d.mu.Lock()
		d.active--
		if pending {
			d.pending--
		}
		d.mu.Unlock()
	}()
	ready := func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		if pending {
			pending = false
			d.pending--
			timer.Stop()
			_ = c.SetDeadline(time.Time{})
		}
		if carrier, ok := c.(interface{ ProtocolReady() }); ok {
			carrier.ProtocolReady()
		}
		if parent, ok := ctx.Value(pluginCarrierReadyKey{}).(func()); ok {
			parent()
		}
	}
	ctx = context.WithValue(ctx, protocolReadyKey{}, ready)
	if err := d.serve(ctx, c, metadata.Source, finish); err != nil {
		return err
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Targets stay owned by the connection, including fallback reads. The initial
// deadline protects the handshake and is promoted for retained cover traffic.
type pluginDialer struct{ timeout time.Duration }

func (d pluginDialer) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	raw, err := (&net.Dialer{Timeout: d.timeout}).DialContext(ctx, network, dst.String())
	if err != nil {
		return nil, err
	}
	c := &contextConn{Conn: raw}
	c.stop = context.AfterFunc(ctx, func() { raw.Close() })
	if handoff, ok := ctx.Value(pluginHandoffKey{}).(*pluginHandoff); ok {
		handoff.track(c)
	}

	return c, nil
}
func (pluginDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("plugin handshake dialer only supports TCP")
}

var _ N.Dialer = pluginDialer{}
