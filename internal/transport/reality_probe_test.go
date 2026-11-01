// SPDX-License-Identifier: GPL-3.0-only
package transport

import (
	"context"
	reality "github.com/xtls/reality"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestCancelledWaiterDoesNotWaitForSharedProbe(t *testing.T) {
	cfg := &reality.Config{Dest: "127.0.0.1:1", ServerNames: map[string]bool{"cancel-test.local": true}}
	keys := make([]string, 3)
	realityRecords.Lock()
	for i := range 3 {
		key := cfg.Dest + " cancel-test.local " + strconv.Itoa(i)
		keys[i] = key
		realityRecords.entries[key] = &recordProbe{refs: 1, ready: make(chan struct{})}
	}
	realityRecords.Unlock()
	defer releaseRealityRecords(keys)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() { _, err := acquireRealityRecords(ctx, cfg, time.Second); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled startup succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled listener waited for shared probe")
	}
	realityRecords.Lock()
	defer realityRecords.Unlock()
	for _, key := range keys {
		if realityRecords.entries[key].refs != 1 {
			t.Fatal("shared probe lease leaked")
		}
	}
}
func TestProbeCancellationClosesAllTargetSockets(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var wg sync.WaitGroup
	accepted := make(chan struct{}, 6)
	closed := make(chan struct{}, 6)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				accepted <- struct{}{}
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				b := make([]byte, 8192)
				for {
					if _, err := c.Read(b); err != nil {
						closed <- struct{}{}
						return
					}
				}
			}()
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	cfg := &reality.Config{Type: "tcp", Dest: listener.Addr().String(), ServerNames: map[string]bool{"localhost": true}}
	go func() { _, err := acquireRealityRecords(ctx, cfg, time.Second); result <- err }()
	for range 6 {
		select {
		case <-accepted:
		case <-time.After(2 * time.Second):
			cancel()
			t.Fatal("probe connection missing")
		}
	}
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("cancelled probe succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("probe ignored cancellation")
	}
	for range 6 {
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Fatal("probe target socket leaked")
		}
	}
	listener.Close()
	<-done
	wg.Wait()
	realityRecords.Lock()
	defer realityRecords.Unlock()
	for key := range realityRecords.entries {
		if len(key) >= len(cfg.Dest) && key[:len(cfg.Dest)] == cfg.Dest {
			t.Fatal("failed probe retained global cache lease")
		}
	}
}
