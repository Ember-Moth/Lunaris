//go:build darwin

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors
// UDP ancillary helpers adapted from Polaris 56d52fb44958ef3cc2a7fb841cd240f8206234b2.
package ingress

import (
	"errors"
	"net"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/unix"
)

func enableUDPDestination(conn *net.UDPConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	local, _ := conn.LocalAddr().(*net.UDPAddr)
	useIPv4 := local == nil || local.IP.To4() != nil
	var controlErr error
	err = raw.Control(func(fd uintptr) {
		if useIPv4 {
			controlErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO, 1)
		} else {
			controlErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1)
		}
	})
	return errors.Join(err, controlErr)
}

func readUDPDestination(conn *net.UDPConn, payload []byte) (int, netip.AddrPort, netip.Addr, error) {
	var control [128]byte
	count, controlCount, _, source, err := conn.ReadMsgUDPAddrPort(payload, control[:])
	if err != nil {
		return count, source, netip.Addr{}, err
	}
	if source.IsValid() {
		source = netip.AddrPortFrom(source.Addr().Unmap(), source.Port())
	}
	return count, source, parseUDPDestination(control[:controlCount]), nil
}

func parseUDPDestination(control []byte) netip.Addr {
	headerLength := unix.CmsgLen(0)
	for len(control) >= headerLength {
		header := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
		messageLength := int(header.Len)
		if messageLength < headerLength || messageLength > len(control) {
			return netip.Addr{}
		}
		data := control[headerLength:messageLength]
		switch {
		case header.Level == unix.IPPROTO_IP && header.Type == unix.IP_PKTINFO && len(data) >= unix.SizeofInet4Pktinfo:
			info := (*unix.Inet4Pktinfo)(unsafe.Pointer(&data[0]))
			return netip.AddrFrom4(info.Addr)
		case header.Level == unix.IPPROTO_IP && header.Type == unix.IP_RECVDSTADDR && len(data) >= 4:
			return netip.AddrFrom4(*(*[4]byte)(unsafe.Pointer(&data[0])))
		case header.Level == unix.IPPROTO_IPV6 && header.Type == unix.IPV6_PKTINFO &&
			len(data) >= unix.SizeofInet6Pktinfo:
			info := (*unix.Inet6Pktinfo)(unsafe.Pointer(&data[0]))
			return netip.AddrFrom16(info.Addr).Unmap()
		}
		step := unix.CmsgSpace(messageLength - headerLength)
		if step <= 0 || step > len(control) {
			return netip.Addr{}
		}
		control = control[step:]
	}
	return netip.Addr{}
}

func marshalUDPSource(address netip.Addr, ipv6 bool) []byte {
	address = address.Unmap()
	if address.Is4() && !ipv6 {
		control := make([]byte, unix.CmsgSpace(unix.SizeofInet4Pktinfo))
		header := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
		header.Level = unix.IPPROTO_IP
		header.Type = unix.IP_PKTINFO
		header.SetLen(unix.CmsgLen(unix.SizeofInet4Pktinfo))
		info := (*unix.Inet4Pktinfo)(unsafe.Pointer(&control[unix.CmsgLen(0)]))
		info.Spec_dst = address.As4()
		return control
	}
	if address.Is6() || address.Is4() && ipv6 {
		control := make([]byte, unix.CmsgSpace(unix.SizeofInet6Pktinfo))
		header := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
		header.Level = unix.IPPROTO_IPV6
		header.Type = unix.IPV6_PKTINFO
		header.SetLen(unix.CmsgLen(unix.SizeofInet6Pktinfo))
		info := (*unix.Inet6Pktinfo)(unsafe.Pointer(&control[unix.CmsgLen(0)]))
		info.Addr = address.As16()
		return control
	}
	return nil
}
