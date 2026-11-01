//go:build linux || darwin

// SPDX-License-Identifier: GPL-3.0-only
package cmd

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

func subscribeNodeSignals(ctx context.Context) (nodeSignals, func()) {
	raw := make(chan os.Signal, 4)
	reload, status := make(chan struct{}, 1), make(chan struct{}, 1)
	done := make(chan struct{})
	var once sync.Once
	stop := func() { once.Do(func() { signal.Stop(raw); close(done) }) }
	signal.Notify(raw, syscall.SIGHUP, syscall.SIGUSR1)
	go func() {
		defer stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case sig := <-raw:
				if sig == syscall.SIGHUP {
					select {
					case reload <- struct{}{}:
					default:
					}
				} else {
					select {
					case status <- struct{}{}:
					default:
					}
				}
			}
		}
	}()
	return nodeSignals{reload: reload, status: status}, stop
}
