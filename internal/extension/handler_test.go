// SPDX-License-Identifier: GPL-3.0-only
package extension

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
	mux "github.com/sagernet/sing-mux"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

type rejectHandler struct{ calls atomic.Int32 }

func (h *rejectHandler) NewConnectionEx(_ context.Context, c net.Conn, _, _ M.Socksaddr, close N.CloseHandlerFunc) {
	h.calls.Add(1)
	c.Close()
	if close != nil {
		close(nil)
	}
}
func (h *rejectHandler) NewPacketConnectionEx(_ context.Context, c N.PacketConn, _, _ M.Socksaddr, close N.CloseHandlerFunc) {
	h.calls.Add(1)
	c.Close()
	if close != nil {
		close(nil)
	}
}
func TestDisabledExtensionsNeverReachEgress(t *testing.T) {
	for _, dst := range []M.Socksaddr{uot.RequestDestination(1), uot.RequestDestination(2), mux.Destination} {
		t.Run(dst.Fqdn, func(t *testing.T) {
			next := new(rejectHandler)
			h, _ := New(Options{}, model.DefaultLimits(), next, nil)
			defer h.Close(context.Background())
			client, server := net.Pipe()
			defer client.Close()
			h.NewConnectionEx(context.Background(), server, M.Socksaddr{}, dst, nil)
			if next.calls.Load() != 0 {
				t.Fatal("disabled extension escaped to egress")
			}
		})
	}
}
func TestTruncatedUOTReleasesHandshakeBudget(t *testing.T) {
	limits := model.DefaultLimits()
	limits.HandshakeTimeout = 40 * time.Millisecond
	limits.MaxPendingHandshakes = 1
	h, _ := New(Options{UDPOverTCP: true}, limits, new(rejectHandler), nil)
	defer h.Close(context.Background())
	client, server := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		h.NewConnectionEx(context.Background(), server, M.Socksaddr{}, uot.RequestDestination(2), nil)
		close(done)
	}()
	if _, err := client.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("UoT header timeout did not close stream")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.pending != 0 || len(h.entries) != 0 {
		t.Fatal("UoT handshake slot leaked")
	}
}
func TestCloseInterruptsIncompleteMuxHeader(t *testing.T) {
	h, _ := New(Options{Multiplex: model.Multiplex{Enabled: true}}, model.DefaultLimits(), new(rejectHandler), nil)
	client, server := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		h.NewConnectionEx(context.Background(), server, M.Socksaddr{}, mux.Destination, nil)
		close(done)
	}()
	if _, err := client.Write([]byte{mux.Version1}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := h.Close(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("mux parser survived Close")
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("carrier was not closed: %v", err)
	}
}

func TestFixedUOTVersionRejectsLegacyBeforeEgress(t *testing.T) {
	next := new(rejectHandler)
	h, err := New(Options{UDPOverTCP: true, UDPOverTCPVersion: 2}, model.DefaultLimits(), next, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close(context.Background())
	client, server := net.Pipe()
	defer client.Close()
	h.NewConnectionEx(context.Background(), server, M.Socksaddr{}, uot.RequestDestination(1), nil)
	if next.calls.Load() != 0 {
		t.Fatal("legacy UoT reached egress under a v2-only policy")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.pending != 0 || len(h.entries) != 0 {
		t.Fatal("rejected UoT consumed handshake resources")
	}
}
