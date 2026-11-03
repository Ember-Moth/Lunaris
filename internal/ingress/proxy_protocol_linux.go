//go:build linux

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors
// Adapted from Polaris 56d52fb44958ef3cc2a7fb841cd240f8206234b2.
package ingress

import (
	"net"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// peekProxyHeader inspects the available TCP prefix without consuming it. Returning
// supported=false lets synthetic and non-socket connections use the portable
// consuming detector.
func peekProxyHeader(conn net.Conn, target []byte, wait bool) (n int, supported bool, wouldBlock bool, err error) {
	syscallConn, ok := conn.(syscall.Conn)
	if !ok {
		return 0, false, false, nil
	}
	rawConn, err := syscallConn.SyscallConn()
	if err != nil {
		return 0, true, false, err
	}
	state := proxyPeekStatePool.Get().(*proxyPeekState)
	state.target = target
	state.wait = wait
	err = rawConn.Read(state.callback)
	n = state.n
	wouldBlock = state.wouldBlock
	operationErr := state.operationErr
	state.reset()
	proxyPeekStatePool.Put(state)
	if err != nil {
		return 0, true, wouldBlock, err
	}
	return n, true, wouldBlock, operationErr
}

var proxyPeekStatePool = sync.Pool{New: func() any {
	state := new(proxyPeekState)
	state.callback = state.read
	return state
}}

type proxyPeekState struct {
	target       []byte
	wait         bool
	n            int
	wouldBlock   bool
	operationErr error
	callback     func(uintptr) bool
}

func (state *proxyPeekState) read(fd uintptr) bool {
	for {
		state.n, _, state.operationErr = unix.Recvfrom(int(fd), state.target, unix.MSG_PEEK)
		if state.operationErr == unix.EINTR {
			continue
		}
		if state.operationErr == unix.EAGAIN || state.operationErr == unix.EWOULDBLOCK {
			state.operationErr = nil
			if state.wait {
				return false
			}
			state.wouldBlock = true
		}
		return true
	}
}

func (state *proxyPeekState) reset() {
	state.target = nil
	state.wait = false
	state.n = 0
	state.wouldBlock = false
	state.operationErr = nil
}
