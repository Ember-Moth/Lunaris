// SPDX-License-Identifier: GPL-3.0-only
package egress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/ingress"
	"github.com/Ember-Moth/Lunaris/internal/route"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type Direct struct{ net.Dialer }

func (d *Direct) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if destination.IsFqdn() {
		if resolver := route.NameResolverFromContext(ctx); resolver != nil {
			addresses, found := route.ResolvedAddressesFromContext(ctx, destination.Fqdn)
			if !found {
				var err error
				addresses, err = resolver.LookupIP(ctx, destination.Fqdn)
				if err != nil {
					return nil, err
				}
			}
			source, bound := ingress.BindingIP(ctx)
			same := false
			for _, ip := range addresses {
				if bound && ip.Unmap().Is4() == source.Is4() {
					same = true
				}
			}
			var result error
			for _, ip := range addresses {
				ip = ip.Unmap()
				if !ip.IsValid() || same && ip.Is4() != source.Is4() {
					continue
				}
				connection, err := d.DialContext(ctx, network, M.Socksaddr{Addr: ip, Port: destination.Port})
				if err == nil {
					return connection, nil
				}
				result = errors.Join(result, err)
			}
			if result == nil {
				result = errors.New("DNS returned no usable addresses")
			}
			return nil, result
		}
	}

	ip, bind := ingress.BindingIP(ctx)
	if !bind || destination.Addr.IsValid() && destination.Addr.Unmap().Is4() != ip.Is4() {
		return d.Dialer.DialContext(ctx, network, destination.String())
	}
	bound := d.Dialer
	switch network {
	case "tcp", "tcp4", "tcp6":
		bound.LocalAddr = &net.TCPAddr{IP: net.IP(ip.AsSlice()), Zone: ip.Zone()}
	case "udp", "udp4", "udp6":
		bound.LocalAddr = &net.UDPAddr{IP: net.IP(ip.AsSlice()), Zone: ip.Zone()}
	default:
		return d.Dialer.DialContext(ctx, network, destination.String())
	}
	selected := familyNetwork(network, ip)
	if destination.IsFqdn() {
		// Let the resolver return both families. LocalAddr selects compatible
		// candidates; forcing tcp4/tcp6 here would turn an other-family-only
		// name into an indistinguishable DNS "no such host" error.
		selected = network
	}
	c, err := bound.DialContext(ctx, selected, destination.String())
	if unavailableSource(err) {
		return d.Dialer.DialContext(ctx, network, destination.String())
	}
	return c, err
}

func (d *Direct) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if ip, ok := ingress.BindingIP(ctx); ok {
		return newSourcePacketConn(ctx, ip, destination)
	}
	var listen net.ListenConfig
	return listen.ListenPacket(ctx, "udp", ":0")
}

func familyNetwork(network string, ip netip.Addr) string {
	if network == "tcp" || network == "udp" {
		if ip.Is4() {
			return network + "4"
		}
		return network + "6"
	}
	return network
}
func unavailableSource(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EADDRNOTAVAIL) {
		return true
	}
	var addr *net.AddrError
	return errors.As(err, &addr) && addr.Err == "no suitable address found"
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
		var addresses []netip.Addr
		var err error
		if resolver := route.NameResolverFromContext(ctx); resolver != nil {
			addresses, err = resolver.LookupIP(ctx, destination.Fqdn)
		} else {
			addresses, err = net.DefaultResolver.LookupNetIP(ctx, "ip", destination.Fqdn)
		}
		cancel()
		if err != nil {
			return err
		}
		if len(addresses) == 0 {
			return errors.New("UDP destination has no addresses")
		}
		address := addresses[0].Unmap()
		preferred, hasSource := ingress.BindingIP(c.ctx)
		for _, candidate := range addresses {
			if hasSource && candidate.Unmap().Is4() == preferred.Is4() || !hasSource && (candidate.Is4() || candidate.Is4In6()) {
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
