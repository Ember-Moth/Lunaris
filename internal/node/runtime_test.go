// SPDX-License-Identifier: GPL-3.0-only
package node

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol/builtin"
)

func TestFailedGenerationReleasesEarlierListener(t *testing.T) {
	first, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	firstAddress := first.Addr().String()
	firstPort := uint16(first.Addr().(*net.TCPAddr).Port)
	first.Close()
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	options := json.RawMessage(`{"method":"aes-128-gcm"}`)
	snapshot := &model.RuntimeConfig{Config: model.NodeConfig{SchemaVersion: 1, Limits: model.DefaultLimits(), Listeners: []model.ListenerSpec{
		{ID: "first", Enabled: true, Protocol: "shadowsocks", Address: "127.0.0.1", Port: firstPort, Network: []string{"tcp"}, Options: options, CredentialRefs: []string{"key"}},
		{ID: "blocked", Enabled: true, Protocol: "shadowsocks", Address: "127.0.0.1", Port: uint16(occupied.Addr().(*net.TCPAddr).Port), Network: []string{"tcp"}, Options: options, CredentialRefs: []string{"key"}},
	}}, Credentials: map[string][]byte{"key": []byte("test-password")}}
	registry, _ := builtin.NewRegistry()
	if runtime, err := Start(context.Background(), snapshot, registry, nil); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		runtime.Close(ctx)
		t.Fatal("conflicting port accepted")
	}
	rebound, err := net.Listen("tcp", firstAddress)
	if err != nil {
		t.Fatalf("earlier listener leaked: %v", err)
	}
	rebound.Close()
}
