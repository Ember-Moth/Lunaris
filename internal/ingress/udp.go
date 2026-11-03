// SPDX-License-Identifier: GPL-3.0-only
package ingress

import (
	"errors"
	"net"
	"net/netip"
)

// LocalPacketConn preserves a datagram's local destination independently of
// its remote peer. No peer-to-local cache can alias two local entry addresses.
type LocalPacketConn interface {
	net.PacketConn
	ReadFromWithLocal([]byte) (int, net.Addr, net.Addr, error)
	WriteToWithLocal([]byte, net.Addr, net.Addr) (int, error)
}
type originPacketConn struct {
	*net.UDPConn
	ipv6 bool
	port int
}

func PacketConn(conn net.PacketConn) (net.PacketConn, error) {
	udp, ok := conn.(*net.UDPConn)
	if !ok {
		return conn, nil
	}
	address, ok := udp.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, errors.New("UDP local endpoint unavailable")
	}
	if ip := AddressIP(address); validLocal(ip) {
		return conn, nil
	}
	if err := enableUDPDestination(udp); err != nil {
		return nil, err
	}
	return &originPacketConn{UDPConn: udp, ipv6: address.IP.To4() == nil, port: address.Port}, nil
}
func (c *originPacketConn) ReadFromWithLocal(p []byte) (int, net.Addr, net.Addr, error) {
	n, remote, local, err := readUDPDestination(c.UDPConn, p)
	if err != nil {
		return n, nil, nil, err
	}
	if !validLocal(local) {
		return 0, nil, nil, errors.New("UDP destination metadata missing")
	}
	return n, net.UDPAddrFromAddrPort(remote), net.UDPAddrFromAddrPort(netip.AddrPortFrom(local, uint16(c.port))), nil
}
func (c *originPacketConn) WriteToWithLocal(p []byte, remote, local net.Addr) (int, error) {
	destination, ok := remote.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("UDP remote endpoint required")
	}
	ip := AddressIP(local)
	if !validLocal(ip) {
		return 0, errors.New("UDP local endpoint required")
	}
	control := marshalUDPSource(ip, c.ipv6)
	if len(control) == 0 {
		return 0, errors.New("UDP source metadata unsupported")
	}
	n, _, err := c.UDPConn.WriteMsgUDP(p, control, destination)
	return n, err
}
func ReadPacket(conn net.PacketConn, p []byte) (int, net.Addr, net.Addr, error) {
	if source, ok := conn.(LocalPacketConn); ok {
		return source.ReadFromWithLocal(p)
	}
	n, remote, err := conn.ReadFrom(p)
	return n, remote, conn.LocalAddr(), err
}
func WritePacket(conn net.PacketConn, p []byte, remote, local net.Addr) (int, error) {
	if source, ok := conn.(LocalPacketConn); ok {
		return source.WriteToWithLocal(p, remote, local)
	}
	return conn.WriteTo(p, remote)
}
