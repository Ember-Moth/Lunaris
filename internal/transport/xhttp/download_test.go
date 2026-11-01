// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package xhttp

import (
	"context"
	"net"
	"testing"
)

func TestSplitDownloadManager(t *testing.T) {
	serverConfig := testTransportConfig(t, ModePacketUp)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(context.Background(), serverConfig, nil, echoHandler{})
	go func() { _ = server.Serve(listener) }()

	clientConfig := serverConfig
	clientConfig.Download = &DownloadConfig{Address: listener.Addr().String(), Transport: serverConfig}
	client := NewClient(ClientOptions{
		Context: context.Background(), Config: clientConfig, Server: listener.Addr().String(), Dial: testDialAddress,
	})
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
		_ = listener.Close()
	})
	assertTransportRoundTrip(t, client)
}
