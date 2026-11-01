// SPDX-License-Identifier: GPL-3.0-only
package transport

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
	X "github.com/Ember-Moth/Lunaris/internal/transport/xhttp"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func (f XHTTPFactory) Build(r ResolvedSpec, b Binding) (Instance, error) {
	if err := model.ValidateLimits(r.Limits); err != nil {
		return nil, err
	}
	if b.Stream == nil || b.Stream.Serve == nil {
		return nil, errors.New("XHTTP requires a stream protocol handler")
	}
	spec := model.ListenerSpec{Transport: r.Transport}
	if len(r.Certificate) > 0 {
		spec.CertificateRef = "resolved"
	}
	if fields := f.Validate(spec); len(fields) > 0 {
		return nil, errors.New(fields[0].Message)
	}
	cfg, err := parseXHTTP(r.Transport)
	if err != nil {
		return nil, err
	}
	total := r.Limits.MaxConnections + r.Limits.MaxUDPSessions
	cfg.ScMaxActiveSessions = min(cfg.ScMaxActiveSessions, total)
	cfg.ScMaxConcurrentRequests = min(cfg.ScMaxConcurrentRequests, 2*total+r.Limits.MaxPendingHandshakes)
	cfg.PendingTimeout = r.Limits.HandshakeTimeout
	return &xhttpInstance{resolved: r, binding: b.Stream, config: cfg, entries: make(map[*xhttpStream]struct{}), events: make(chan InstanceEvent, 4), done: make(chan struct{})}, nil
}

type xhttpInstance struct {
	resolved        ResolvedSpec
	binding         *StreamHandler
	config          X.Config
	mu              sync.Mutex
	started, closed bool
	ctx             context.Context
	cancel          context.CancelFunc
	inner           Instance
	server          *X.Server
	entries         map[*xhttpStream]struct{}
	pending         int
	wg              sync.WaitGroup
	once            sync.Once
	done            chan struct{}
	events          chan InstanceEvent
	closeErr        error
}
type xhttpStream struct {
	owner   *xhttpInstance
	conn    net.Conn
	timer   *time.Timer
	pending bool
	done    chan struct{}
	cancel  context.CancelFunc
	once    sync.Once
}

func (s *xhttpInstance) Events() <-chan InstanceEvent { return s.events }
func (s *xhttpInstance) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.inner.(interface{ Addr() net.Addr }); ok {
		return a.Addr()
	}
	return nil
}
func (s *xhttpInstance) Start(parent context.Context) error {
	s.mu.Lock()
	if s.started || s.closed {
		s.mu.Unlock()
		return errors.New("XHTTP instance cannot be restarted")
	}
	if err := parent.Err(); err != nil {
		s.mu.Unlock()
		return err
	}
	s.started = true
	s.ctx, s.cancel = context.WithCancel(parent)
	if s.binding.Start != nil {
		if err := s.binding.Start(); err != nil {
			s.mu.Unlock()
			s.close()
			return err
		}
	}
	s.server = X.NewServer(s.ctx, s.config, nil, s)
	// An HTTP carrier may hold many protocol sessions, and packet-up uses
	// separate physical upload/download sockets. Admission for the reconstructed
	// streams is maintained independently below.
	r := s.resolved
	r.Limits.MaxConnections = min(65536, max(2, 2*(r.Limits.MaxConnections+r.Limits.MaxUDPSessions)))
	handler := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		authenticated(request.Context())
		s.server.ServeHTTP(w, request)
	})
	var err error
	if (XHTTPFactory{}).CapabilitiesFor(model.ListenerSpec{Transport: r.Transport}).UDP {
		r.Network = []string{"udp"}
		binding := configuredHTTP3Binding(handler, r.Limits.HandshakeTimeout, http3Options{maxHeaderBytes: s.config.ServerMaxHeaderBytes, config: s.config.ServerQUICConfig(), onConnection: X.ConfigureQUICConnection})
		s.inner, err = (QUICFactory{}).Build(r, Binding{QUIC: binding})
	} else {
		r.Network = []string{"tcp"}
		version := ""
		if r.Transport.XHTTP != nil {
			version = r.Transport.XHTTP.HTTPVersion
		}
		s.inner, err = newHTTPInstance(r, Binding{HTTP: handler}, httpOptions{allowPlain: true, keepAlive: true, version: version, maxHeaderBytes: s.config.ServerMaxHeaderBytes})
	}
	if err == nil {
		err = s.inner.Start(s.ctx)
	}
	if err == nil {
		s.events <- InstanceEvent{State: "running"}
	}
	s.mu.Unlock()
	if err != nil {
		s.close()
		return err
	}
	context.AfterFunc(s.ctx, s.close)
	go func() {
		for {
			select {
			case event := <-s.inner.Events():
				if event.State == "failed" {
					s.events <- event
					s.close()
					return
				}
			case <-s.done:
				return
			}
		}
	}()
	return nil
}
func (s *xhttpInstance) NewConnectionEx(ctx context.Context, c net.Conn, source, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	s.mu.Lock()
	if s.closed || ctx.Err() != nil || s.pending >= s.resolved.Limits.MaxPendingHandshakes || len(s.entries) >= s.resolved.Limits.MaxConnections+s.resolved.Limits.MaxUDPSessions {
		s.mu.Unlock()
		_ = c.Close()
		if onClose != nil {
			onClose(errors.New("XHTTP stream admission limit reached"))
		}
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	entry := &xhttpStream{cancel: cancel, owner: s, conn: c, pending: true, done: make(chan struct{})}
	s.entries[entry] = struct{}{}
	s.pending++
	s.wg.Add(1)
	_ = c.SetDeadline(time.Now().Add(s.resolved.Limits.HandshakeTimeout))
	entry.timer = time.AfterFunc(s.resolved.Limits.HandshakeTimeout, func() { cancel(); _ = c.Close() })
	s.mu.Unlock()
	ctx = context.WithValue(ctx, protocolReadyKey{}, entry.ready)
	go func() {
		defer s.wg.Done()
		defer entry.finish()
		close := N.OnceClose(func(err error) {
			entry.once.Do(func() {
				entry.cancel()
				_ = c.Close()
				close(entry.done)
				if onClose != nil {
					onClose(err)
				}
			})
		})
		err := s.binding.Serve(ctx, c, source, close)
		if err != nil {
			close(err)
			return
		}
		select {
		case <-entry.done:
		case <-ctx.Done():
			close(ctx.Err())
		}
	}()
}
func (e *xhttpStream) ready() {
	s := e.owner
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.pending {
		e.pending = false
		s.pending--
		e.timer.Stop()
		_ = e.conn.SetDeadline(time.Time{})
	}
}
func (e *xhttpStream) finish() {
	e.cancel()
	_ = e.conn.Close()
	s := e.owner
	s.mu.Lock()
	if e.pending {
		e.pending = false
		s.pending--
	}
	e.timer.Stop()
	delete(s.entries, e)
	s.mu.Unlock()
}
func (s *xhttpInstance) close() {
	s.once.Do(func() {
		s.mu.Lock()
		s.closed = true
		if s.cancel != nil {
			s.cancel()
		}
		inner, server := s.inner, s.server
		entries := make([]*xhttpStream, 0, len(s.entries))
		for e := range s.entries {
			entries = append(entries, e)
		}
		s.mu.Unlock()
		go func() {
			for _, e := range entries {
				_ = e.conn.Close()
			}
			coreDone := make(chan error, 1)
			go func() {
				if server != nil {
					coreDone <- server.Close()
				} else {
					coreDone <- nil
				}
			}()
			if inner != nil {
				s.closeErr = inner.Stop(context.Background())
			}
			s.closeErr = errors.Join(s.closeErr, <-coreDone)
			s.wg.Wait()
			if s.binding.Close != nil {
				s.closeErr = errors.Join(s.closeErr, s.binding.Close())
			}
			s.events <- InstanceEvent{State: "stopped"}
			close(s.done)
		}()
	})
}
func (s *xhttpInstance) Stop(ctx context.Context) error {
	s.close()
	select {
	case <-s.done:
		return s.closeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}
