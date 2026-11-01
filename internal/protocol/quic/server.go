// SPDX-License-Identifier: GPL-3.0-only
package quic

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"sync"

	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/Ember-Moth/Lunaris/internal/transport"
	"github.com/gofrs/uuid/v5"
	Q "github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing-quic/tuic"
	"github.com/sagernet/sing/common/logger"
)

type service interface {
	Start(net.PacketConn) error
	Close() error
}
type Server struct {
	resolved        protocol.ResolvedListenerSpec
	deps            protocol.Dependencies
	options         Options
	tls             *tls.Config
	mu              sync.Mutex
	started, closed bool
	ctx             context.Context
	cancel          context.CancelFunc
	socket          net.PacketConn
	transport       *Q.Transport
	service         service
	total, pending  int
	wg              sync.WaitGroup
	once            sync.Once
	done            chan struct{}
	events          chan protocol.InstanceEvent
}

func newServer(r protocol.ResolvedListenerSpec, d protocol.Dependencies, o Options, t *tls.Config) *Server {
	if d.Logger == nil {
		d.Logger = logger.NOP()
	}
	return &Server{resolved: r, deps: d, options: o, tls: t, done: make(chan struct{}), events: make(chan protocol.InstanceEvent, 4)}
}
func (s *Server) Events() <-chan protocol.InstanceEvent { return s.events }
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.socket == nil {
		return nil
	}
	return s.socket.LocalAddr()
}
func (s *Server) Start(parent context.Context) error {
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
	cfg := &serverTLS{TLS: &transport.TLS{Config: s.tls, Timeout: r.Limits.HandshakeTimeout}, owner: s}
	qopts := qtls.QUICOptions{IdleTimeout: r.Limits.UDPIdleTimeout, MaxConcurrentStreams: r.Limits.MaxConnections, StreamReceiveWindow: 1 << 20, ConnectionReceiveWindow: 4 << 20}
	if r.Spec.Protocol == "hysteria2" {
		// Reserve one HTTP/3 authentication stream in addition to payload flows.
		qopts.MaxConcurrentStreams++
	}
	var err error
	if r.Spec.Protocol == "hysteria2" {
		svc, e := hysteria2.NewService[string](hysteria2.ServiceOptions{Context: s.ctx, Logger: s.deps.Logger, TLSConfig: cfg, QUICOptions: qopts, IgnoreClientBandwidth: true, UDPTimeout: r.Limits.UDPIdleTimeout, Handler: s.deps.Handler})
		err = e
		if err == nil {
			passwords := make([]string, len(r.Spec.CredentialRefs))
			for i, ref := range r.Spec.CredentialRefs {
				passwords[i] = string(r.Credentials[ref])
			}
			svc.UpdateUsers(r.Spec.CredentialRefs, passwords)
			s.service = svc
		}
	} else {
		svc, e := tuic.NewService[string](tuic.ServiceOptions{Context: s.ctx, Logger: s.deps.Logger, TLSConfig: cfg, QUICOptions: qopts, CongestionControl: s.options.CongestionControl, AuthTimeout: r.Limits.HandshakeTimeout, UDPTimeout: r.Limits.UDPIdleTimeout, Handler: s.deps.Handler})
		err = e
		if err == nil {
			users := make([]string, len(s.options.Users))
			ids := make([][16]byte, len(users))
			passwords := make([]string, len(users))
			for i, u := range s.options.Users {
				users[i] = u.CredentialRef
				ids[i] = [16]byte(uuid.FromStringOrNil(u.UUID))
				passwords[i] = string(r.Credentials[u.CredentialRef])
			}
			svc.UpdateUsers(users, ids, passwords)
			s.service = svc
		}
	}
	if err != nil {
		return err
	}
	s.socket, err = (&net.ListenConfig{}).ListenPacket(s.ctx, "udp", net.JoinHostPort(r.Spec.Address, strconv.Itoa(int(r.Spec.Port))))
	if err != nil {
		return err
	}
	if err = s.service.Start(s.socket); err != nil {
		return err
	}
	context.AfterFunc(s.ctx, s.close)
	s.events <- protocol.InstanceEvent{State: "running"}
	return nil
}
func (s *Server) close() {
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
			s.events <- protocol.InstanceEvent{State: "stopped"}
			close(s.done)
		}()
	})
}
func (s *Server) Stop(ctx context.Context) error {
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
	once sync.Once
	s    *Server
}

func (v *slot) ready() { v.once.Do(func() { v.s.mu.Lock(); v.s.pending--; v.s.mu.Unlock() }) }
func (s *Server) admit(ctx context.Context, _ *Q.ClientInfo) (context.Context, error) {
	s.mu.Lock()
	if s.closed || s.total >= s.resolved.Limits.MaxConnections || s.pending >= s.resolved.Limits.MaxPendingHandshakes {
		s.mu.Unlock()
		return nil, errors.New("QUIC connection limit reached")
	}
	s.total++
	s.pending++
	s.wg.Add(1)
	s.mu.Unlock()
	v := &slot{s: s}
	context.AfterFunc(ctx, func() { v.ready(); s.mu.Lock(); s.total--; s.mu.Unlock(); s.wg.Done() })
	return context.WithValue(ctx, slotKey{}, v), nil
}

// Closing quic-go's listener alone leaves accepted sessions alive. Own and close
// the transport too, and account for handshakes before protocol authentication.
type serverTLS struct {
	*transport.TLS
	owner *Server
}

func (t *serverTLS) Listen(c net.PacketConn, cfg *Q.Config) (qtls.Listener, error) {
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
func (t *serverTLS) ListenEarly(net.PacketConn, *Q.Config) (qtls.EarlyListener, error) {
	return nil, errors.New("QUIC 0-RTT is disabled")
}
func (t *serverTLS) ConfigureHTTP3() { http3.ConfigureTLSConfig(t.Config) }

type trackedListener struct {
	qtls.Listener
	owner *Server
}

func (l *trackedListener) Accept(ctx context.Context) (*Q.Conn, error) {
	c, err := l.Listener.Accept(ctx)
	if err == nil {
		if v, ok := c.Context().Value(slotKey{}).(*slot); ok {
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
		case s.events <- protocol.InstanceEvent{State: "failed", Err: errors.New("QUIC listener failed")}:
		default:
		}
		go s.close()
	}
	return nil, err
}
