// SPDX-License-Identifier: GPL-3.0-only
package outbound

import (
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// QUIC protocol packet sessions expose read deadlines but no write-deadline
// setter. Closing only that logical UDP session interrupts a stalled stream
// write without closing the shared QUIC connection or another UDP session.
type packetDeadline struct {
	N.NetPacketConn
	mu                       sync.Mutex
	writeMu                  sync.Mutex
	deadline                 time.Time
	timer                    *time.Timer
	closed, writing, expired bool
	operation                uint64
	once                     sync.Once
	err                      error
}

func (c *packetDeadline) SetDeadline(t time.Time) error {
	return errors.Join(c.SetReadDeadline(t), c.SetWriteDeadline(t))
}
func (c *packetDeadline) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.deadline = t
	c.armLocked()
	return nil
}
func (c *packetDeadline) armLocked() {
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	if !c.writing || c.deadline.IsZero() {
		return
	}
	operation := c.operation
	c.timer = time.AfterFunc(time.Until(c.deadline), func() {
		c.mu.Lock()
		if c.closed || !c.writing || c.operation != operation || c.deadline.IsZero() || time.Now().Before(c.deadline) {
			c.mu.Unlock()
			return
		}
		c.expired = true
		c.mu.Unlock()
		c.Close()
	})
}
func (c *packetDeadline) write(work func() error) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return net.ErrClosed
	}
	if !c.deadline.IsZero() && !time.Now().Before(c.deadline) {
		c.mu.Unlock()
		return os.ErrDeadlineExceeded
	}
	c.operation++
	c.writing = true
	c.expired = false
	c.armLocked()
	c.mu.Unlock()
	err := work()
	c.mu.Lock()
	c.writing = false
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	expired := c.expired
	c.mu.Unlock()
	if expired {
		return os.ErrDeadlineExceeded
	}
	return err
}
func (c *packetDeadline) WriteTo(p []byte, dst net.Addr) (int, error) {
	n := 0
	err := c.write(func() error { var err error; n, err = c.NetPacketConn.WriteTo(p, dst); return err })
	return n, err
}
func (c *packetDeadline) WritePacket(b *buf.Buffer, dst M.Socksaddr) error {
	defer b.Release()
	_, err := c.WriteTo(b.Bytes(), dst)
	return err
}
func (c *packetDeadline) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		if c.timer != nil {
			c.timer.Stop()
		}
		c.mu.Unlock()
		c.err = c.NetPacketConn.Close()
	})
	return c.err
}
