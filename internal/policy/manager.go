// SPDX-License-Identifier: GPL-3.0-only
package policy

import (
	"context"
	"errors"
	"net"
	"sync"

	dnsmod "github.com/Ember-Moth/Lunaris/internal/dns"
	"github.com/Ember-Moth/Lunaris/internal/egress"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/route"
	M "github.com/sagernet/sing/common/metadata"
)

var ErrBlocked = errors.New("routing policy blocked destination")

type Manager struct {
	ctx     context.Context
	mu      sync.Mutex
	entries map[string]*Generation
}
type Generation struct {
	parent   *Manager
	key      string
	refs     int
	router   *route.Router
	resolver *dnsmod.Resolver
	hijack   bool
	done     chan struct{}
}
type Lease struct {
	limits     model.Limits
	generation *Generation
	once       sync.Once
	last       bool
}

func NewManager(ctx context.Context) *Manager {
	return &Manager{ctx: ctx, entries: map[string]*Generation{}}
}
func (m *Manager) Acquire(snapshot *model.RuntimeConfig) (*Lease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ctx.Err(); err != nil {
		return nil, err
	}
	if existing := m.entries[snapshot.PolicyDigest]; existing != nil {
		existing.refs++
		return &Lease{generation: existing, limits: snapshot.Config.Limits}, nil
	}
	generation := &Generation{parent: m, key: snapshot.PolicyDigest, refs: 1, done: make(chan struct{})}
	if snapshot.PolicyDigest != "" {
		compiled, err := compile(snapshot)
		if err != nil {
			return nil, err
		}
		compiled.options.Context = m.ctx
		generation.router = route.NewRouter(compiled.routes)
		generation.resolver = dnsmod.NewResolver(compiled.dns, compiled.options)
		generation.hijack = compiled.hijack
	}
	m.entries[generation.key] = generation
	return &Lease{generation: generation, limits: snapshot.Config.Limits}, nil
}
func (l *Lease) Close(ctx context.Context) error {
	l.once.Do(func() {
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
			if g.resolver == nil {
				close(g.done)
			} else {
				go func() { g.resolver.Close(); close(g.done) }()
			}
		}
	})
	// Only the final lease owns asynchronous generation cleanup.
	if !l.last {
		return nil
	}
	select {
	case <-l.generation.done:
		return nil
	default:
	}
	select {
	case <-l.generation.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (l *Lease) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	work, decision, err := l.generation.choose(ctx, dst, route.TCP)
	if err != nil {
		return nil, err
	}
	if decision.Target != route.Direct {
		return nil, ErrBlocked
	}
	return (&egress.Direct{}).DialContext(work, network, dst)
}
func (l *Lease) ListenPacket(ctx context.Context, dst M.Socksaddr) (net.PacketConn, error) {
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
