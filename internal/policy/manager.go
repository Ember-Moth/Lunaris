// SPDX-License-Identifier: GPL-3.0-only
package policy

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	dnsmod "github.com/Ember-Moth/Lunaris/internal/dns"
	"github.com/Ember-Moth/Lunaris/internal/egress"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/outbound"
	"github.com/Ember-Moth/Lunaris/internal/route"
	M "github.com/sagernet/sing/common/metadata"
)

var ErrBlocked = errors.New("routing policy blocked destination")

type Manager struct {
	ctx     context.Context
	mu      sync.Mutex
	entries map[string]*Generation
	key     [32]byte
}
type Generation struct {
	parent    *Manager
	key       string
	refs      int
	router    *route.Router
	resolver  *dnsmod.Resolver
	hijack    bool
	done      chan struct{}
	ctx       context.Context
	cancel    context.CancelFunc
	outbounds map[route.Target]outbound.Client
	closeErr  error
}
type Lease struct {
	limits     model.Limits
	generation *Generation
	once       sync.Once
	last       bool
	closed     atomic.Bool
}

func NewManager(ctx context.Context) *Manager {
	m := &Manager{ctx: ctx, entries: map[string]*Generation{}}
	_, _ = rand.Read(m.key[:])
	return m
}
func (m *Manager) Acquire(snapshot *model.RuntimeConfig) (*Lease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ctx.Err(); err != nil {
		return nil, err
	}
	key := snapshot.PolicyDigest
	if len(snapshot.Config.Outbounds) > 0 {
		raw, _ := json.Marshal(struct {
			Policy          string
			Credentials     map[string][]byte
			Dial, Handshake time.Duration
		}{snapshot.PolicyDigest, OutboundCredentials(snapshot), snapshot.Config.Limits.DialTimeout, snapshot.Config.Limits.HandshakeTimeout})
		mac := hmac.New(sha256.New, m.key[:])
		_, _ = mac.Write(raw)
		key = hex.EncodeToString(mac.Sum(nil))
	}
	if existing := m.entries[key]; existing != nil {
		existing.refs++
		return &Lease{generation: existing, limits: snapshot.Config.Limits}, nil
	}
	ctx, cancel := context.WithCancel(m.ctx)
	generation := &Generation{parent: m, key: key, refs: 1, done: make(chan struct{}), ctx: ctx, cancel: cancel, outbounds: make(map[route.Target]outbound.Client)}
	if snapshot.PolicyDigest != "" {
		compiled, err := compile(snapshot)
		if err != nil {
			cancel()
			return nil, err
		}
		compiled.options.Context = ctx
		generation.router = route.NewRouter(compiled.routes)
		generation.resolver = dnsmod.NewResolver(compiled.dns, compiled.options)
		generation.hijack = compiled.hijack
	}
	registry := outbound.NewRegistry()
	for _, spec := range snapshot.Config.Outbounds {
		client, err := registry.Build(ctx, spec, snapshot.Credentials, generationDialer{generation}, snapshot.Config.Limits)
		if err != nil {
			cancel()
			for _, client := range generation.outbounds {
				_ = client.Close(context.Background())
			}
			if generation.resolver != nil {
				generation.resolver.Close()
			}
			return nil, err
		}
		generation.outbounds[route.Target(spec.ID)] = client
	}
	m.entries[generation.key] = generation
	return &Lease{generation: generation, limits: snapshot.Config.Limits}, nil
}
func (l *Lease) Close(ctx context.Context) error {
	l.once.Do(func() {
		l.closed.Store(true)
		g := l.generation
		m := g.parent
		m.mu.Lock()
		g.refs--
		l.last = g.refs == 0
		if l.last {
			delete(m.entries, g.key)
		}
		m.mu.Unlock()
		if l.last {
			g.cancel()
			go func() {
				defer close(g.done)
				for _, client := range g.outbounds {
					g.closeErr = errors.Join(g.closeErr, client.Close(context.Background()))
				}
				if g.resolver != nil {
					g.resolver.Close()
				}
			}()
		}
	})
	// Only the final lease owns asynchronous generation cleanup.
	if !l.last {
		return nil
	}
	select {
	case <-l.generation.done:
		return l.generation.closeErr
	default:
	}
	select {
	case <-l.generation.done:
		return l.generation.closeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (l *Lease) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	if l.closed.Load() {
		return nil, net.ErrClosed
	}
	work, decision, err := l.generation.choose(ctx, dst, route.TCP)
	if err != nil {
		return nil, err
	}
	if decision.Target != route.Direct {
		client, ok := l.generation.outbounds[decision.Target]
		if !ok {
			return nil, errors.New("selected outbound is unavailable")
		}
		if dst.IsFqdn() && len(decision.Addresses) > 0 {
			var last error
			for _, address := range decision.Addresses {
				conn, err := client.DialContext(work, network, M.Socksaddr{Addr: address.Unmap(), Port: dst.Port})
				if err == nil {
					return conn, nil
				}
				last = errors.Join(last, err)
			}
			return nil, last
		}
		return client.DialContext(work, network, dst)
	}
	return (&egress.Direct{}).DialContext(work, network, dst)
}
func (l *Lease) ListenPacket(ctx context.Context, dst M.Socksaddr) (net.PacketConn, error) {
	if l.closed.Load() {
		return nil, net.ErrClosed
	}
	if _, _, err := l.generation.choose(ctx, dst, route.UDP); err != nil {
		return nil, err
	}
	if l.generation.key == "" {
		return (&egress.Direct{}).ListenPacket(ctx, dst)
	}
	return newPacketConn(context.WithoutCancel(ctx), l.generation, l.limits), nil
}
func (g *Generation) context(ctx context.Context) context.Context {
	if g.resolver == nil {
		return ctx
	}
	return route.WithDNSHijack(route.WithNameResolver(ctx, g.resolver), g.hijack)
}
func (g *Generation) choose(ctx context.Context, dst M.Socksaddr, network route.Network) (context.Context, route.Decision, error) {
	if g.ctx.Err() != nil {
		return ctx, route.Decision{}, net.ErrClosed
	}
	ctx = g.context(ctx)
	if g.router == nil {
		return ctx, route.Decision{Target: route.Direct}, nil
	}
	kind := route.DestinationIP
	if dst.IsFqdn() {
		kind = route.DestinationDomain
	}
	decision := g.router.Route(ctx, route.Request{Domain: dst.AddrString(), Address: dst.Addr, Kind: kind, Network: network, Port: dst.Port})
	if decision.Target == route.Block {
		return ctx, decision, ErrBlocked
	}
	// An IP rule cannot be bypassed by resolving again after a failed route lookup.
	if decision.ResolveError != nil {
		return ctx, decision, decision.ResolveError
	}
	ctx = route.WithResolvedAddresses(ctx, dst.Fqdn, decision.Addresses)
	return ctx, decision, nil
}

// Context supplies the same generation resolver to protocol target handshakes.
func (l *Lease) Context(ctx context.Context) context.Context { return l.generation.context(ctx) }

// OutboundCredentials returns only the material that affects outbound clients.
// It feeds private generation keys and the runtime's keyed listener fingerprint.
func OutboundCredentials(snapshot *model.RuntimeConfig) map[string][]byte {
	result := make(map[string][]byte)
	for _, spec := range snapshot.Config.Outbounds {
		if spec.CredentialRef != "" {
			result[spec.CredentialRef] = snapshot.Credentials[spec.CredentialRef]
		}
	}
	return result
}

// Proxy servers use the configured resolver and ingress binding, but do not
// re-enter destination routing (in particular a final proxy route).
type generationDialer struct{ g *Generation }

func (d generationDialer) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	return (&egress.Direct{}).DialContext(d.g.context(ctx), network, dst)
}
func (d generationDialer) ListenPacket(ctx context.Context, dst M.Socksaddr) (net.PacketConn, error) {
	return (&egress.Direct{}).ListenPacket(d.g.context(ctx), dst)
}
