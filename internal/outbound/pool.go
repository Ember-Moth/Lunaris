// SPDX-License-Identifier: GPL-3.0-only
package outbound

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/ingress"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const maxSourceClients = 64

// Stateful protocol sessions must never migrate between ingress bindings.
type sourcePool struct {
	ctx     context.Context
	cancel  context.CancelFunc
	dialer  N.Dialer
	timeout time.Duration
	build   func(context.Context, N.Dialer) (ProtocolClient, error)
	mu      sync.Mutex
	closed  bool
	entries map[netip.Addr]*sourceEntry
	once    sync.Once
	err     error
}
type sourceEntry struct {
	client   ProtocolClient
	physical *ownedDialer
}

func newSourcePool(ctx context.Context, dialer N.Dialer, timeout time.Duration, build func(context.Context, N.Dialer) (ProtocolClient, error)) *sourcePool {
	ctx, cancel := context.WithCancel(ctx)
	return &sourcePool{ctx: ctx, cancel: cancel, dialer: dialer, timeout: timeout, build: build, entries: make(map[netip.Addr]*sourceEntry)}
}
func (p *sourcePool) get(ctx context.Context) (ProtocolClient, error) {
	ip, bind := ingress.BindingIP(ctx)
	if !bind {
		ip = netip.Addr{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if e := p.entries[ip]; e != nil {
		return e.client, nil
	}
	if len(p.entries) >= maxSourceClients {
		return nil, errors.New("outbound source-client limit reached")
	}
	root := p.ctx
	if bind {
		root = ingress.WithLocalIP(root, ip)
	}
	d := newOwnedDialer(root, p.dialer, p.timeout, ip)
	c, err := p.build(root, d)
	if err != nil {
		d.Close()
		return nil, err
	}
	p.entries[ip] = &sourceEntry{client: c, physical: d}
	return c, nil
}
func (p *sourcePool) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	c, err := p.get(ctx)
	if err != nil {
		return nil, err
	}
	return c.DialContext(ctx, network, dst)
}
func (p *sourcePool) ListenPacket(ctx context.Context, dst M.Socksaddr) (net.PacketConn, error) {
	c, err := p.get(ctx)
	if err != nil {
		return nil, err
	}
	return c.ListenPacket(ctx, dst)
}
func (p *sourcePool) Close() error {
	p.once.Do(func() {
		p.mu.Lock()
		p.closed = true
		p.cancel()
		entries := make([]*sourceEntry, 0, len(p.entries))
		for _, e := range p.entries {
			entries = append(entries, e)
		}
		p.mu.Unlock()
		for _, e := range entries {
			p.err = errors.Join(p.err, e.client.Close(), e.physical.Close())
		}
	})
	return p.err
}

// A library's background QUIC offer can outlive its foreground waiter. Track
// physical sockets independently so retirement joins their creation and closes
// even a socket that was not yet published as a usable protocol connection.
type ownedDialer struct {
	ctx         context.Context
	cancel      context.CancelFunc
	dialer      N.Dialer
	timeout     time.Duration
	source      netip.Addr
	mu          sync.Mutex
	closed      bool
	connections map[*ownedConn]struct{}
	active      sync.WaitGroup
}

func newOwnedDialer(ctx context.Context, dialer N.Dialer, timeout time.Duration, source netip.Addr) *ownedDialer {
	ctx, cancel := context.WithCancel(ctx)
	return &ownedDialer{ctx: ctx, cancel: cancel, dialer: dialer, timeout: timeout, source: source, connections: make(map[*ownedConn]struct{})}
}
func (d *ownedDialer) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	d.mu.Lock()
	if d.closed || d.ctx.Err() != nil {
		d.mu.Unlock()
		return nil, net.ErrClosed
	}
	d.active.Add(1)
	d.mu.Unlock()
	defer d.active.Done()
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	stop := context.AfterFunc(d.ctx, cancel)
	defer func() { stop(); cancel() }()
	if d.source.IsValid() {
		ctx = ingress.WithLocalIP(ctx, d.source)
	}
	raw, err := d.dialer.DialContext(ctx, network, dst)
	if err != nil {
		return nil, err
	}
	// QUIC offers run in the library's background lifetime context. Bound the
	// entire pending offer, including authentication after TLS, until a usable
	// stream/session is handed back and clears this temporary socket deadline.
	if network == "udp" {
		if err = raw.SetDeadline(time.Now().Add(d.timeout)); err != nil {
			raw.Close()
			return nil, err
		}
	}
	c := &ownedConn{Conn: raw, owner: d}
	d.mu.Lock()
	if d.closed || ctx.Err() != nil || d.ctx.Err() != nil {
		d.mu.Unlock()
		raw.Close()
		return nil, net.ErrClosed
	}
	d.connections[c] = struct{}{}
	d.mu.Unlock()
	return c, nil
}
func (d *ownedDialer) ready() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for c := range d.connections {
		_ = c.Conn.SetDeadline(time.Time{})
	}
}
func (d *ownedDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("stateful outbound requires a connected transport socket")
}
func (d *ownedDialer) Close() error {
	d.mu.Lock()
	d.closed = true
	d.cancel()
	connections := make([]*ownedConn, 0, len(d.connections))
	for c := range d.connections {
		connections = append(connections, c)
	}
	d.mu.Unlock()
	for _, c := range connections {
		c.Close()
	}
	d.active.Wait()
	return nil
}

type ownedConn struct {
	net.Conn
	owner *ownedDialer
	once  sync.Once
	err   error
}

func (c *ownedConn) Close() error {
	c.once.Do(func() { c.err = c.Conn.Close(); c.owner.mu.Lock(); delete(c.owner.connections, c); c.owner.mu.Unlock() })
	return c.err
}
func (c *ownedConn) Upstream() any { return c.Conn }
