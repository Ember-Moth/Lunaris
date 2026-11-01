// SPDX-License-Identifier: GPL-3.0-or-later

package xhttp

import (
	"errors"
	"net"
	"sync"
)

type h1ConnPool struct {
	mu     sync.Mutex
	idle   []*h1Conn
	limit  int
	closed bool
}

func newH1ConnPool(limit int) *h1ConnPool {
	return &h1ConnPool{limit: max(1, limit)}
}

func (pool *h1ConnPool) Get() *h1Conn {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if pool.closed || len(pool.idle) == 0 {
		return nil
	}
	last := len(pool.idle) - 1
	conn := pool.idle[last]
	pool.idle[last] = nil
	pool.idle = pool.idle[:last]
	return conn
}

func (pool *h1ConnPool) Put(conn *h1Conn) {
	pool.mu.Lock()
	if !pool.closed && len(pool.idle) < pool.limit {
		pool.idle = append(pool.idle, conn)
		pool.mu.Unlock()
		return
	}
	pool.mu.Unlock()
	_ = conn.Close()
}

func (pool *h1ConnPool) Close() error {
	pool.mu.Lock()
	pool.closed = true
	idle := pool.idle
	pool.idle = nil
	pool.mu.Unlock()
	var result error
	for _, conn := range idle {
		result = errors.Join(result, conn.Close())
	}
	return result
}

var _ net.Conn = (*h1Conn)(nil)
