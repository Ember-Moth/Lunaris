// SPDX-License-Identifier: GPL-3.0-only
package transport

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"sync"

	"github.com/Ember-Moth/Lunaris/internal/ingress"
	"github.com/Ember-Moth/Lunaris/internal/model"
	Q "github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	qtls "github.com/sagernet/sing-quic"
)

type quicServer struct {
	resolved        ResolvedSpec
	binding         *QUICHandler
	tls             *tls.Config
	mu              sync.Mutex
	started, closed bool
	ctx             context.Context
	cancel          context.CancelFunc
	socket          net.PacketConn
	transport       *Q.Transport
	service         QUICService
	total, pending  int
	wg              sync.WaitGroup
	once            sync.Once
	done            chan struct{}
	events          chan InstanceEvent
}

type QUICFactory struct{}

func (QUICFactory) Capabilities() Capabilities {
	return Capabilities{Type: "quic", UDP: true, TLS: true, UDPStreams: true}
}
func (QUICFactory) Validate(s model.ListenerSpec) []model.FieldError {
	if len(s.Transport.Plugin) > 0 {
		return field("transport.plugin", "plugin settings require a plugin transport")
	}
	if s.CertificateRef == "" {
		return field("certificate_ref", "QUIC requires a TLS certificate")
	}
	return validatePlain(s)
}
func (QUICFactory) Build(r ResolvedSpec, b Binding) (Instance, error) {
	if err := model.ValidateLimits(r.Limits); err != nil {
		return nil, err
	}
	if b.HTTP != nil {
		b.QUIC = http3Binding(b.HTTP, r.Limits.HandshakeTimeout)
	}
	if b.QUIC == nil || b.QUIC.NewService == nil {
		return nil, errors.New("QUIC protocol handler required")
	}
	if b.QUIC.ReservedStreams < 0 || b.QUIC.ReservedStreams > 16 {
		return nil, errors.New("invalid reserved QUIC stream count")
	}
	cfg, err := serverTLSConfig(r, b.QUIC.ALPN)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, errors.New("QUIC certificate required")
	}
	cfg.MinVersion = tls.VersionTLS13
	return &quicServer{resolved: r, binding: b.QUIC, tls: cfg, done: make(chan struct{}), events: make(chan InstanceEvent, 4)}, nil
}

func (s *quicServer) Events() <-chan InstanceEvent { return s.events }
func (s *quicServer) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.socket == nil {
		return nil
	}
	return s.socket.LocalAddr()
}
func (s *quicServer) Start(parent context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started || s.closed {
		return errors.New("QUIC instance cannot be restarted")
	}
	if err := parent.Err(); err != nil {
		return err
	}
	s.started = true
	s.ctx, s.cancel = context.WithCancel(parent)
	r := s.resolved
	cfg := &quicTLS{TLS: &TLS{Config: s.tls, Timeout: r.Limits.HandshakeTimeout}, owner: s}
	qopts := qtls.QUICOptions{IdleTimeout: r.Limits.UDPIdleTimeout, MaxConcurrentStreams: r.Limits.MaxConnections, StreamReceiveWindow: 1 << 20, ConnectionReceiveWindow: 4 << 20}
	qopts.MaxConcurrentStreams += s.binding.ReservedStreams
	var err error
	s.service, err = s.binding.NewService(s.ctx, cfg, qopts)
	if err != nil {
		return err
	}
	if s.service == nil {
		return errors.New("QUIC protocol constructor returned no service")
	}
	s.socket, err = (&net.ListenConfig{}).ListenPacket(s.ctx, "udp", net.JoinHostPort(r.Address, strconv.Itoa(int(r.Port))))
	if err != nil {
		return err
	}
	if err = s.service.Start(s.socket); err != nil {
		return err
	}
	context.AfterFunc(s.ctx, s.close)
	s.events <- InstanceEvent{State: "running"}
	return nil
}
func (s *quicServer) close() {
	s.once.Do(func() {
		s.mu.Lock()
		s.closed = true
		if s.cancel != nil {
			s.cancel()
		}
		svc, t, sock := s.service, s.transport, s.socket
		s.mu.Unlock()
		go func() {
			if svc != nil {
				svc.Close()
			}
			if t != nil {
				t.Close()
			}
			if sock != nil {
				sock.Close()
			}
			s.wg.Wait()
			s.events <- InstanceEvent{State: "stopped"}
			close(s.done)
		}()
	})
}
func (s *quicServer) Stop(ctx context.Context) error {
	s.close()
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type slotKey struct{}
type slot struct {
	once  sync.Once
	s     *quicServer
	local *ingress.LocalSlot
}

func (v *slot) ready() { v.once.Do(func() { v.s.mu.Lock(); v.s.pending--; v.s.mu.Unlock() }) }
func (s *quicServer) admit(ctx context.Context, _ *Q.ClientInfo) (context.Context, error) {
	s.mu.Lock()
	if s.closed || s.total >= s.resolved.Limits.MaxConnections || s.pending >= s.resolved.Limits.MaxPendingHandshakes {
		s.mu.Unlock()
		return nil, errors.New("QUIC connection limit reached")
	}
	s.total++
	s.pending++
	s.wg.Add(1)
	s.mu.Unlock()
	ctx, local := ingress.WithLocalSlot(ctx)
	v := &slot{s: s, local: local}
	context.AfterFunc(ctx, func() { v.ready(); s.mu.Lock(); s.total--; s.mu.Unlock(); s.wg.Done() })
	return context.WithValue(ctx, slotKey{}, v), nil
}

// Closing quic-go's listener alone leaves accepted sessions alive. Own and close
// the transport too, and account for handshakes before protocol authentication.
type quicTLS struct {
	*TLS
	owner *quicServer
}

func (t *quicTLS) Listen(c net.PacketConn, cfg *Q.Config) (qtls.Listener, error) {
	s := t.owner
	// HTTP/3 needs control/QPACK streams; TUIC also authenticates on a
	// unidirectional stream. These must work even with one allowed UDP flow.
	cfg.MaxIncomingUniStreams = int64(max(4, s.resolved.Limits.MaxUDPSessions+1))
	cfg.HandshakeIdleTimeout = s.resolved.Limits.HandshakeTimeout
	key := new(Q.StatelessResetKey)
	if _, err := rand.Read(key[:]); err != nil {
		return nil, err
	}
	tr := &Q.Transport{Conn: c, ConnContext: s.admit, StatelessResetKey: key, VerifySourceAddress: func(net.Addr) bool { return true }}
	s.transport = tr // Start holds the lifecycle lock.
	l, err := tr.Listen(t.Config, cfg)
	if err != nil {
		return nil, err
	}
	return &trackedListener{Listener: l, owner: s}, nil
}
func (t *quicTLS) ListenEarly(net.PacketConn, *Q.Config) (qtls.EarlyListener, error) {
	return nil, errors.New("QUIC 0-RTT is disabled")
}
func (t *quicTLS) ConfigureHTTP3() { http3.ConfigureTLSConfig(t.Config) }

type trackedListener struct {
	qtls.Listener
	owner *quicServer
}

func (l *trackedListener) Accept(ctx context.Context) (*Q.Conn, error) {
	c, err := l.Listener.Accept(ctx)
	if err == nil {
		if v, ok := c.Context().Value(slotKey{}).(*slot); ok {
			v.local.Set(c.LocalAddr())
			v.ready()
		}
		return c, nil
	}
	s := l.owner
	s.mu.Lock()
	closed := s.closed || s.ctx.Err() != nil
	s.mu.Unlock()
	if !closed {
		select {
		case s.events <- InstanceEvent{State: "failed", Err: errors.New("QUIC listener failed")}:
		default:
		}
		go s.close()
	}
	return nil, err
}
