// SPDX-License-Identifier: GPL-3.0-only
package policy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	dnsmod "github.com/Ember-Moth/Lunaris/internal/dns"
	"github.com/Ember-Moth/Lunaris/internal/egress"
	"github.com/Ember-Moth/Lunaris/internal/ingress"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/route"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/pipe"
)

type packetResponse struct {
	data   []byte
	source M.Socksaddr
	err    error
}
type packetConn struct {
	ctx           context.Context
	cancel        context.CancelFunc
	generation    *Generation
	limits        model.Limits
	mu            sync.Mutex
	closed        bool
	direct        net.PacketConn
	allowed       map[netip.AddrPort]bool
	destinations  map[string]bool
	writeDeadline time.Time
	writeMu       sync.Mutex
	readDeadline  pipe.Deadline
	responses     chan packetResponse
	wg            sync.WaitGroup
	once          sync.Once
}

func newPacketConn(ctx context.Context, g *Generation, limits model.Limits) *packetConn {
	ctx, cancel := context.WithCancel(ctx)
	return &packetConn{ctx: ctx, cancel: cancel, generation: g, limits: limits, allowed: map[netip.AddrPort]bool{}, destinations: map[string]bool{}, readDeadline: pipe.MakeDeadline(), responses: make(chan packetResponse, 1)}
}
func (c *packetConn) operation() (context.Context, context.CancelFunc) {
	c.mu.Lock()
	deadline := c.writeDeadline
	c.mu.Unlock()
	maximum := time.Now().Add(c.limits.DialTimeout)
	if deadline.IsZero() || maximum.Before(deadline) {
		deadline = maximum
	}
	return context.WithDeadline(c.ctx, deadline)
}
func (c *packetConn) WritePacket(b *buf.Buffer, destination M.Socksaddr) error {
	defer b.Release()
	return c.write(b.Bytes(), destination)
}
func (c *packetConn) WriteTo(p []byte, destination net.Addr) (int, error) {
	if err := c.write(p, M.SocksaddrFromNet(destination).Unwrap()); err != nil {
		return 0, err
	}
	return len(p), nil
}
func (c *packetConn) write(p []byte, dst M.Socksaddr) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if !dst.IsValid() || dst.Port == 0 || len(p) > 65535 {
		return errors.New("invalid routed UDP packet")
	}
	ctx, cancel := c.operation()
	defer cancel()
	ctx, decision, err := c.generation.choose(ctx, dst, route.UDP)
	if err != nil {
		return err
	}
	if decision.Target == route.DNS {
		if err := c.admit("dns:" + dst.String()); err != nil {
			return err
		}
		response, err := c.generation.resolver.ExchangePacket(ctx, p)
		if errors.Is(err, route.ErrNoDNSResolverMatch) {
			response, err = exchangeOriginalDNS(ctx, dst, p)
		}
		if err != nil {
			return err
		}
		select {
		case c.responses <- packetResponse{data: response, source: dst}:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if dst.IsFqdn() {
		addresses, found := route.ResolvedAddressesFromContext(ctx, dst.Fqdn)
		if !found {
			addresses, err = c.generation.resolver.LookupIP(ctx, dst.Fqdn)
			if err != nil {
				return err
			}
		}
		if len(addresses) == 0 {
			return errors.New("DNS returned no UDP destination")
		}
		selected := addresses[0].Unmap()
		source, preserve := ingress.BindingIP(ctx)
		for _, ip := range addresses {
			ip = ip.Unmap()
			if preserve && ip.Is4() == source.Is4() {
				selected = ip
				break
			}
		}
		dst = M.Socksaddr{Addr: selected, Port: dst.Port}
	}
	if err := c.admit("direct:" + dst.String()); err != nil {
		return err
	}
	socket, err := c.socket(ctx, dst)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.allowed[dst.AddrPort()] = true
	c.mu.Unlock()
	deadline, _ := ctx.Deadline()
	if err := socket.SetWriteDeadline(deadline); err != nil {
		return err
	}
	_, err = socket.WriteTo(p, dst.UDPAddr())
	return err
}
func (c *packetConn) admit(key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	if !c.destinations[key] && len(c.destinations) >= c.limits.MaxUDPDestinations {
		return errors.New("UDP destination limit reached")
	}
	c.destinations[key] = true
	return nil
}
func (c *packetConn) socket(ctx context.Context, dst M.Socksaddr) (net.PacketConn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, net.ErrClosed
	}
	if c.direct != nil {
		return c.direct, nil
	}
	socket, err := (&egress.Direct{}).ListenPacket(ctx, dst)
	if err != nil {
		return nil, err
	}
	c.direct = socket
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		buffer := make([]byte, 65535)
		for {
			n, source, err := socket.ReadFrom(buffer)
			if err != nil {
				select {
				case c.responses <- packetResponse{err: err}:
				case <-c.ctx.Done():
				}
				return
			}
			address := M.SocksaddrFromNet(source).Unwrap()
			c.mu.Lock()
			allowed := c.allowed[address.AddrPort()]
			c.mu.Unlock()
			if !allowed {
				continue
			}
			value := packetResponse{data: append([]byte(nil), buffer[:n]...), source: address}
			select {
			case c.responses <- value:
			case <-c.ctx.Done():
				return
			}
		}
	}()
	return socket, nil
}
func (c *packetConn) receive() (packetResponse, error) {
	select {
	case <-c.ctx.Done():
		return packetResponse{}, net.ErrClosed
	default:
	}
	select {
	case value := <-c.responses:
		return value, value.err
	case <-c.ctx.Done():
		return packetResponse{}, net.ErrClosed
	case <-c.readDeadline.Wait():
		return packetResponse{}, os.ErrDeadlineExceeded
	}
}
func (c *packetConn) ReadPacket(b *buf.Buffer) (M.Socksaddr, error) {
	value, err := c.receive()
	if err != nil {
		return M.Socksaddr{}, err
	}
	if b.FreeLen() < len(value.data) {
		return M.Socksaddr{}, io.ErrShortBuffer
	}
	_, err = b.Write(value.data)
	return value.source, err
}
func (c *packetConn) ReadFrom(p []byte) (int, net.Addr, error) {
	value, err := c.receive()
	if err != nil {
		return 0, nil, err
	}
	n := copy(p, value.data)
	if n < len(value.data) {
		return n, value.source, io.ErrShortBuffer
	}
	return n, value.source, nil
}
func (c *packetConn) LocalAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.direct != nil {
		return c.direct.LocalAddr()
	}
	return &net.UDPAddr{}
}
func (c *packetConn) SetReadDeadline(t time.Time) error { c.readDeadline.Set(t); return nil }
func (c *packetConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.writeDeadline = t
	if c.direct != nil {
		return c.direct.SetWriteDeadline(t)
	}
	return nil
}
func (c *packetConn) SetDeadline(t time.Time) error {
	return errors.Join(c.SetReadDeadline(t), c.SetWriteDeadline(t))
}
func (c *packetConn) Close() error {
	c.once.Do(func() {
		c.cancel()
		c.mu.Lock()
		c.closed = true
		if c.direct != nil {
			c.direct.Close()
		}
		c.mu.Unlock()
		c.wg.Wait()
	})
	return nil
}
func exchangeOriginalDNS(ctx context.Context, dst M.Socksaddr, query []byte) ([]byte, error) {
	connection, err := (&egress.Direct{}).DialContext(ctx, "udp", dst)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { connection.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		connection.SetDeadline(deadline)
	}
	if _, err := connection.Write(query); err != nil {
		return nil, err
	}
	response := make([]byte, 65535)
	n, err := connection.Read(response)
	if err != nil {
		return nil, err
	}
	response = response[:n]
	if err := dnsmod.ValidatePacketResponse(query, response); err != nil {
		return nil, err
	}
	return response, nil
}

var _ N.PacketConn = (*packetConn)(nil)
var _ net.PacketConn = (*packetConn)(nil)
