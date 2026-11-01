// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package xhttp

import (
	"context"
	"io"
	"math"
	"net"
	"testing"
	"time"
)

type blockingPacketClient struct {
	started chan struct{}
	release chan struct{}
}

func (client *blockingPacketClient) IsClosed() bool { return false }
func (client *blockingPacketClient) Close() error   { return nil }

func (client *blockingPacketClient) openStream(context.Context, string, string, io.Reader, bool) (io.ReadCloser, net.Addr, net.Addr, error) {
	return nil, nil, nil, net.ErrClosed
}

func (client *blockingPacketClient) postPacket(ctx context.Context, _, _, _ string, _ []byte, onWritten func()) error {
	onWritten()
	client.started <- struct{}{}
	select {
	case <-client.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestUploadPacketsBoundsPendingResponses(t *testing.T) {
	config, err := Parse("", "/x", ModePacketUp, `{
		"scMaxEachPostBytes":4,"scMinPostsIntervalMs":-1,"scMaxBufferedPosts":2,
		"xmux":{"maxConnections":1,"hMaxRequestTimes":1000}
	}`)
	if err != nil {
		t.Fatal(err)
	}
	fake := &blockingPacketClient{started: make(chan struct{}, 4), release: make(chan struct{})}
	selected := &xmuxClient{conn: fake}
	selected.leftRequests.Store(math.MaxInt32)
	client := &Client{config: config, server: "127.0.0.1:443"}
	pipe := newUploadPipe(4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lease := newXMUXLease(selected, selected)
	defer lease.Close()
	go client.uploadPackets(ctx, pipe, "session", selected, lease)
	go func() {
		for range 4 {
			_, _ = pipe.Write([]byte("data"))
		}
	}()
	for index := range 2 {
		select {
		case <-fake.started:
		case <-time.After(time.Second):
			t.Fatalf("upload %d did not start (limit %d)", index+1, config.ScMaxBufferedPosts)
		}
	}
	select {
	case <-fake.started:
		t.Fatal("in-flight upload limit was exceeded")
	case <-time.After(25 * time.Millisecond):
	}
	close(fake.release)
	select {
	case <-fake.started:
	case <-time.After(time.Second):
		t.Fatal("upload did not resume after a response completed")
	}
}
