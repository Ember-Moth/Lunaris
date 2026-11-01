// SPDX-License-Identifier: GPL-3.0-only
package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
	X "github.com/Ember-Moth/Lunaris/internal/transport/xhttp"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func testXHTTPInstance(t *testing.T, mode string, serve ServeFunc) (Instance, *X.Client) {
	t.Helper()
	r := ResolvedSpec{Address: "127.0.0.1", Limits: model.DefaultLimits(), Transport: model.Transport{Type: "xhttp", Path: "/x", XHTTP: &model.XHTTP{Mode: mode, HTTPVersion: "h1"}}}
	instance, err := (XHTTPFactory{}).Build(r, Binding{Stream: &StreamHandler{Serve: serve}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err = instance.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := instance.Stop(ctx); err != nil {
			t.Error(err)
		}
	})
	cfg, err := X.Parse("", "/x", mode, `{"scMinPostsIntervalMs":1}`)
	if err != nil {
		t.Fatal(err)
	}
	client := X.NewClient(X.ClientOptions{Context: ctx, Config: cfg, Server: instance.(interface{ Addr() net.Addr }).Addr().String(), Dial: func(ctx context.Context, address string, _ *tls.Config) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}})
	t.Cleanup(func() { client.Close() })
	return instance, client
}
func TestXHTTPClientCloseCancelsProtocolContext(t *testing.T) {
	for _, mode := range []string{X.ModePacketUp, X.ModeStreamUp, X.ModeStreamOne} {
		t.Run(mode, func(t *testing.T) {
			entered := make(chan context.Context, 1)
			_, client := testXHTTPInstance(t, mode, func(ctx context.Context, c net.Conn, _ M.Socksaddr, _ N.CloseHandlerFunc) error {
				if _, err := io.ReadFull(c, make([]byte, 1)); err != nil {
					return err
				}
				authenticated(ctx)
				entered <- ctx
				return nil
			})
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			c, err := client.DialContext(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = c.Write([]byte{1}); err != nil {
				t.Fatal(err)
			}
			var protocolCtx context.Context
			select {
			case protocolCtx = <-entered:
			case <-ctx.Done():
				t.Fatal("protocol was not entered")
			}
			c.Close()
			select {
			case <-protocolCtx.Done():
			case <-ctx.Done():
				t.Fatal("client cancellation did not reach protocol/egress context")
			}
		})
	}
}
func TestXHTTPStopDeadlineRetainsCleanupOwnership(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	instance, client := testXHTTPInstance(t, X.ModePacketUp, func(ctx context.Context, c net.Conn, _ M.Socksaddr, _ N.CloseHandlerFunc) error {
		if _, err := io.ReadFull(c, make([]byte, 1)); err != nil {
			return err
		}
		authenticated(ctx)
		close(entered)
		<-release
		return ctx.Err()
	})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := client.DialContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte{1})
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("protocol was not entered")
	}
	short, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stop()
	if err = instance.Stop(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Stop returned before protocol cleanup: %v", err)
	}
	close(release)
	released = true
	if err = instance.Stop(ctx); err != nil {
		t.Fatal("cleanup did not converge", err)
	}
}
