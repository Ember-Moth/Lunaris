// SPDX-License-Identifier: GPL-3.0-only
package relay

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
	M "github.com/sagernet/sing/common/metadata"
)

type lateDialer struct {
	started chan struct{}
	release chan struct{}
	result  net.Conn
}

func (d *lateDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	close(d.started)
	<-d.release
	return d.result, nil
}
func (*lateDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	panic("unexpected UDP dial")
}

func TestCloseCancelsPendingFlowAndClosesLateUpstream(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	upstream, observer := net.Pipe()
	defer observer.Close()
	dialer := &lateDialer{started: make(chan struct{}), release: make(chan struct{}), result: upstream}
	handler := New(context.Background(), dialer, model.DefaultLimits())
	var callbacks atomic.Int32
	handler.NewConnectionEx(context.Background(), client, M.Socksaddr{}, M.ParseSocksaddr("127.0.0.1:80"), func(error) { callbacks.Add(1) })
	<-dialer.started
	closed := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() { closed <- handler.Close(ctx) }()
	<-handler.ctx.Done()
	close(dialer.release)
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	observer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := observer.Read(make([]byte, 1)); err == nil {
		t.Fatal("late connection was not closed")
	}
	if tcp, udp := handler.Active(); tcp != 0 || udp != 0 {
		t.Fatalf("flow leaked: %d/%d", tcp, udp)
	}
	if callbacks.Load() != 1 {
		t.Fatalf("close callback called %d times", callbacks.Load())
	}
}
