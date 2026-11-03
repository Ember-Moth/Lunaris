// SPDX-License-Identifier: GPL-3.0-only
package outbound

import (
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	N "github.com/sagernet/sing/common/network"
)

type blockingPacket struct {
	N.NetPacketConn
	entered, release, closed chan struct{}
	enterOnce, closeOnce     sync.Once
}

func (p *blockingPacket) WriteTo(b []byte, _ net.Addr) (int, error) {
	p.enterOnce.Do(func() { close(p.entered) })
	select {
	case <-p.release:
		return len(b), nil
	case <-p.closed:
		return 0, net.ErrClosed
	}
}
func (p *blockingPacket) SetReadDeadline(time.Time) error  { return nil }
func (p *blockingPacket) SetWriteDeadline(time.Time) error { return os.ErrInvalid }
func (p *blockingPacket) Close() error                     { p.closeOnce.Do(func() { close(p.closed) }); return nil }
func newBlockingPacket() *blockingPacket {
	return &blockingPacket{entered: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
}

func TestQUICPacketWriteDeadlineInterruptsBlockedStream(t *testing.T) {
	blocked := newBlockingPacket()
	c := &packetDeadline{NetPacketConn: blocked}
	defer c.Close()
	if err := c.SetDeadline(time.Time{}); err != nil {
		t.Fatal("clear deadline rejected", err)
	}
	result := make(chan error, 1)
	go func() { _, err := c.WriteTo([]byte("packet"), &net.UDPAddr{}); result <- err }()
	<-blocked.entered
	if err := c.SetWriteDeadline(time.Now().Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("UDP stream write stayed blocked")
	}
	select {
	case <-blocked.closed:
	default:
		t.Fatal("expired session not closed")
	}
}
func TestQUICPacketPastDeadlineDoesNotSendAndCanBeReset(t *testing.T) {
	raw := newBlockingPacket()
	c := &packetDeadline{NetPacketConn: raw}
	defer c.Close()
	c.SetWriteDeadline(time.Now().Add(-time.Second))
	if _, err := c.WriteTo([]byte("packet"), &net.UDPAddr{}); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	select {
	case <-raw.entered:
		t.Fatal("expired write was sent")
	default:
	}
	if err := c.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	close(raw.release)
	if n, err := c.WriteTo([]byte("packet"), &net.UDPAddr{}); err != nil || n != 6 {
		t.Fatal("reset deadline did not allow writing", n, err)
	}
}
