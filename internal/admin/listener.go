// SPDX-License-Identifier: GPL-3.0-only
package admin

import (
	"net"
	"sync"
)

// Listener lets the process close remaining HTTP connections after a bounded drain.
type Listener struct {
	net.Listener
	mu          sync.Mutex
	closed      bool
	connections map[*trackedConn]struct{}
}

func TrackListener(listener net.Listener) *Listener {
	return &Listener{Listener: listener, connections: make(map[*trackedConn]struct{})}
}

func (l *Listener) Accept() (net.Conn, error) {
	for {
		connection, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			connection.Close()
			return nil, net.ErrClosed
		}
		if len(l.connections) >= 128 {
			l.mu.Unlock()
			connection.Close()
			continue
		}
		tracked := &trackedConn{Conn: connection, owner: l}
		l.connections[tracked] = struct{}{}
		l.mu.Unlock()
		return tracked, nil
	}
}

func (l *Listener) Close() error {
	l.mu.Lock()
	l.closed = true
	l.mu.Unlock()
	return l.Listener.Close()
}

func (l *Listener) CloseConnections() {
	l.mu.Lock()
	connections := make([]*trackedConn, 0, len(l.connections))
	for connection := range l.connections {
		connections = append(connections, connection)
	}
	l.mu.Unlock()
	for _, connection := range connections {
		connection.Close()
	}
}

type trackedConn struct {
	net.Conn
	owner *Listener
	once  sync.Once
	err   error
}

func (c *trackedConn) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		c.owner.mu.Lock()
		delete(c.owner.connections, c)
		c.owner.mu.Unlock()
	})
	return c.err
}
