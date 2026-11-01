// SPDX-License-Identifier: GPL-3.0-only
package egress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type Direct struct{ net.Dialer }

func (d *Direct) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d.Dialer.DialContext(ctx, network, destination.String())
}

func (d *Direct) ListenPacket(ctx context.Context, _ M.Socksaddr) (net.PacketConn, error) {
	var listen net.ListenConfig
	return listen.ListenPacket(ctx, "udp", ":0")
}

var _ N.Dialer = (*Direct)(nil)

// PacketConn resolves each packet destination and only accepts responses from
// endpoints this association actually contacted. Its destination set is bounded.
type PacketConn struct {
	net.PacketConn
	ctx             context.Context
	timeout         time.Duration
	maxDestinations int
	mu              sync.Mutex
	allowed         map[netip.AddrPort]struct{}
}

func NewPacketConn(ctx context.Context, conn net.PacketConn, timeout time.Duration, maxDestinations int) *PacketConn {
	return &PacketConn{PacketConn: conn, ctx: ctx, timeout: timeout, maxDestinations: maxDestinations, allowed: make(map[netip.AddrPort]struct{})}
}

func (c *PacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	if !destination.IsValid() || destination.Port == 0 {
		return errors.New("invalid UDP destination")
	}
	if destination.IsFqdn() {
		ctx, cancel := context.WithTimeout(c.ctx, c.timeout)
		addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", destination.Fqdn)
		cancel()
		if err != nil {
			return err
		}
		if len(addresses) == 0 {
			return errors.New("UDP destination has no addresses")
		}
		address := addresses[0].Unmap()
		for _, candidate := range addresses {
			if candidate.Is4() || candidate.Is4In6() {
				address = candidate.Unmap()
				break
			}
		}
		destination = M.Socksaddr{Addr: address, Port: destination.Port}
	}
	endpoint := netip.AddrPortFrom(destination.Addr.Unmap(), destination.Port)
	c.mu.Lock()
	_, known := c.allowed[endpoint]
	if !known && len(c.allowed) >= c.maxDestinations {
		c.mu.Unlock()
		return errors.New("UDP destination limit reached")
	}
	c.allowed[endpoint] = struct{}{}
	c.mu.Unlock()
	if err := c.SetWriteDeadline(time.Now().Add(c.timeout)); err != nil {
		return err
	}
	_, err := c.WriteTo(buffer.Bytes(), net.UDPAddrFromAddrPort(endpoint))
	return err
}

func (c *PacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	for {
		n, address, err := c.ReadFrom(buffer.FreeBytes())
		if err != nil {
			return M.Socksaddr{}, err
		}
		source := M.SocksaddrFromNet(address).Unwrap()
		c.mu.Lock()
		_, allowed := c.allowed[source.AddrPort()]
		c.mu.Unlock()
		if !allowed {
			continue
		}
		buffer.Truncate(n)
		return source, nil
	}
}

var _ N.PacketConn = (*PacketConn)(nil)
