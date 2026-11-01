// SPDX-License-Identifier: GPL-3.0-only
package node

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol/builtin"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	M "github.com/sagernet/sing/common/metadata"
)

func freePort(t *testing.T) uint16 {
	t.Helper()
	for range 20 {
		tcp, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		udp, err := net.ListenPacket("udp", tcp.Addr().String())
		port := uint16(tcp.Addr().(*net.TCPAddr).Port)
		tcp.Close()
		if err == nil {
			udp.Close()
			return port
		}
	}
	t.Fatal("cannot reserve test endpoint")
	return 0
}

func realConfig(t *testing.T) *model.RuntimeConfig {
	t.Helper()
	a, b := freePort(t), freePort(t)
	for a == b {
		b = freePort(t)
	}
	return &model.RuntimeConfig{Config: model.NodeConfig{SchemaVersion: 1, Limits: model.DefaultLimits(), Listeners: []model.ListenerSpec{
		{ID: "a", Name: "first", Enabled: true, Protocol: "shadowsocks", Address: "127.0.0.1", Port: a, Network: []string{"tcp", "udp"}, Options: json.RawMessage(`{"method":"aes-128-gcm"}`), CredentialRefs: []string{"a"}},
		{ID: "b", Name: "second", Enabled: true, Protocol: "shadowsocks", Address: "127.0.0.1", Port: b, Network: []string{"tcp", "udp"}, Options: json.RawMessage(`{"method":"aes-128-gcm"}`), CredentialRefs: []string{"b"}},
	}}, Credentials: map[string][]byte{"a": []byte("p2-password-a"), "b": []byte("p2-password-b")}}
}

func cloneConfig(t *testing.T, input *model.RuntimeConfig) *model.RuntimeConfig {
	t.Helper()
	registry, _ := builtin.NewRegistry()
	result, err := registry.Normalize(input)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func startReal(t *testing.T, input *model.RuntimeConfig) *Runtime {
	t.Helper()
	registry, _ := builtin.NewRegistry()
	runtime, err := Start(context.Background(), input, registry, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := runtime.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return runtime
}

func listenerStatus(t *testing.T, r *Runtime, id string) ListenerStatus {
	t.Helper()
	for _, status := range r.Snapshot().Listeners {
		if status.ID == id {
			return status
		}
	}
	t.Fatalf("missing listener %s", id)
	return ListenerStatus{}
}

func echoTarget(t *testing.T) net.Addr {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	t.Cleanup(func() { listener.Close(); <-done })
	return listener.Addr()
}

func proxyClient(t *testing.T, port uint16, password string, target net.Addr) net.Conn {
	t.Helper()
	raw, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmtPort(port)), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	raw.SetDeadline(time.Now().Add(3 * time.Second))
	method, err := shadowaead.New("aes-128-gcm", nil, password)
	if err != nil {
		raw.Close()
		t.Fatal(err)
	}
	conn, err := method.DialConn(raw, M.SocksaddrFromNet(target))
	if err != nil {
		raw.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func fmtPort(port uint16) string { return fmt.Sprintf("%d", port) }

func roundTrip(t *testing.T, conn net.Conn, message string) {
	t.Helper()
	conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.WriteString(conn, message); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(message))
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != message {
		t.Fatal("incorrect echo")
	}
}

func TestApplyNoOpAndMetadataPreserveConnections(t *testing.T) {
	target := echoTarget(t)
	input := realConfig(t)
	runtime := startReal(t, input)
	client := proxyClient(t, input.Config.Listeners[0].Port, string(input.Credentials["a"]), target)
	roundTrip(t, client, "before")
	before := listenerStatus(t, runtime, "a")
	equivalent := cloneConfig(t, input)
	equivalent.Config.Listeners[0].Options = json.RawMessage("{\n \"method\": \"aes-128-gcm\" }")
	equivalent.Config.Listeners[0].Network = []string{"udp", "tcp"}
	equivalent.Config.Listeners[0], equivalent.Config.Listeners[1] = equivalent.Config.Listeners[1], equivalent.Config.Listeners[0]
	result, err := runtime.Apply(context.Background(), equivalent)
	if err != nil || result.Outcome != "no_change" {
		t.Fatalf("unexpected no-op: %+v %v", result, err)
	}
	equivalent.Config.Listeners[1].Name = "renamed"
	equivalent.Config.Limits.ShutdownTimeout = 2 * time.Second
	result, err = runtime.Apply(context.Background(), equivalent)
	if err != nil {
		t.Fatal(err)
	}
	after := listenerStatus(t, runtime, "a")
	if after.Generation != before.Generation || after.SpecDigest != before.SpecDigest || after.Name != "renamed" {
		t.Fatalf("metadata restarted listener: %+v -> %+v", before, after)
	}
	if result.Revision != 2 || runtime.ShutdownTimeout() != 2*time.Second {
		t.Fatal("metadata was not published")
	}
	roundTrip(t, client, "after")
	// Neither caller mutation nor mutation of a returned view may alter active state.
	equivalent.Credentials["a"][0] = 'X'
	after.Network[0] = "invalid"
	if listenerStatus(t, runtime, "a").Network[0] != "tcp" {
		t.Fatal("status shares runtime memory")
	}
	roundTrip(t, proxyClient(t, input.Config.Listeners[0].Port, "p2-password-a", target), "owned snapshot")
}

func TestCredentialRotationClosesOnlyAffectedFlows(t *testing.T) {
	target := echoTarget(t)
	input := realConfig(t)
	runtime := startReal(t, input)
	a := proxyClient(t, input.Config.Listeners[0].Port, "p2-password-a", target)
	b := proxyClient(t, input.Config.Listeners[1].Port, "p2-password-b", target)
	roundTrip(t, a, "first")
	roundTrip(t, b, "second")
	beforeA, beforeB := listenerStatus(t, runtime, "a"), listenerStatus(t, runtime, "b")
	changed := cloneConfig(t, input)
	changed.Credentials["a"] = []byte("rotated-password-a")
	plan, err := runtime.Plan(changed)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Changes[0].Action != "replace" || plan.Changes[1].Action != "keep" {
		t.Fatalf("incorrect plan: %+v", plan)
	}
	result, err := runtime.Apply(context.Background(), changed)
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "applied" || runtime.Snapshot().Degraded {
		t.Fatalf("unexpected result: %+v", result)
	}
	a.SetReadDeadline(time.Now().Add(time.Second))
	_, err = a.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("old flow survived")
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("old flow was not closed")
	}
	roundTrip(t, b, "still alive")
	if listenerStatus(t, runtime, "a").Generation == beforeA.Generation || listenerStatus(t, runtime, "b").Generation != beforeB.Generation {
		t.Fatal("wrong instances rebuilt")
	}
	roundTrip(t, proxyClient(t, changed.Config.Listeners[0].Port, "rotated-password-a", target), "new password")
	old := proxyClient(t, changed.Config.Listeners[0].Port, "p2-password-a", target)
	if _, err := old.Read(make([]byte, 1)); err == nil {
		t.Fatal("old password still accepted")
	}
	encoded, _ := json.Marshal(runtime.Snapshot())
	if bytes.Contains(encoded, []byte("rotated-password-a")) || bytes.Contains(encoded, []byte("p2-password-b")) {
		t.Fatal("status exposed a credential")
	}
}

func TestUDPCredentialRotationRejectsOldDatagrams(t *testing.T) {
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 4096)
		for {
			n, addr, err := listener.ReadFrom(buffer)
			if err != nil {
				return
			}
			_, _ = listener.WriteTo(buffer[:n], addr)
		}
	}()
	t.Cleanup(func() { listener.Close(); <-done })
	input := realConfig(t)
	runtime := startReal(t, input)
	raw, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", fmtPort(input.Config.Listeners[0].Port)))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	oldMethod, _ := shadowaead.New("aes-128-gcm", nil, "p2-password-a")
	oldClient := oldMethod.DialPacketConn(raw)
	raw.SetDeadline(time.Now().Add(time.Second))
	if _, err := oldClient.WriteTo([]byte("old"), listener.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := oldClient.ReadFrom(make([]byte, 256)); err != nil {
		t.Fatal(err)
	}
	changed := cloneConfig(t, input)
	changed.Credentials["a"] = []byte("p2-udp-new-password")
	if _, err := runtime.Apply(context.Background(), changed); err != nil {
		t.Fatal(err)
	}
	raw.SetDeadline(time.Now().Add(150 * time.Millisecond))
	if _, err := oldClient.WriteTo([]byte("must reject"), listener.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := oldClient.ReadFrom(make([]byte, 256)); err == nil {
		t.Fatal("old UDP credential accepted")
	}
	newMethod, _ := shadowaead.New("aes-128-gcm", nil, "p2-udp-new-password")
	newClient := newMethod.DialPacketConn(raw)
	raw.SetDeadline(time.Now().Add(time.Second))
	if _, err := newClient.WriteTo([]byte("new"), listener.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 256)
	n, _, err := newClient.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:n]) != "new" {
		t.Fatal("incorrect new UDP reply")
	}
}

func TestFailedApplyRestoresOldConfigurationAndCredentials(t *testing.T) {
	target := echoTarget(t)
	input := realConfig(t)
	runtime := startReal(t, input)
	kept := proxyClient(t, input.Config.Listeners[1].Port, "p2-password-b", target)
	roundTrip(t, kept, "kept")
	before := runtime.Snapshot()
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	changed := cloneConfig(t, input)
	changed.Config.Listeners[0].Port = uint16(occupied.Addr().(*net.TCPAddr).Port)
	changed.Credentials["a"] = []byte("must-not-be-published")
	result, err := runtime.Apply(context.Background(), changed)
	if err == nil || result.Outcome != "rolled_back" {
		t.Fatalf("expected rollback: %+v %v", result, err)
	}
	after := runtime.Snapshot()
	if after.Revision != before.Revision || after.Degraded || after.RecoveryRequired {
		t.Fatalf("incorrect recovery status: %+v", after)
	}
	roundTrip(t, kept, "uninterrupted")
	roundTrip(t, proxyClient(t, input.Config.Listeners[0].Port, "p2-password-a", target), "old credential restored")
	if listenerStatus(t, runtime, "a").Generation <= before.Listeners[0].Generation {
		t.Fatal("restored instance generation was reused")
	}
}

func TestPortSwapAndDisableRemove(t *testing.T) {
	target := echoTarget(t)
	input := realConfig(t)
	runtime := startReal(t, input)
	changed := cloneConfig(t, input)
	changed.Config.Listeners[0].Port, changed.Config.Listeners[1].Port = changed.Config.Listeners[1].Port, changed.Config.Listeners[0].Port
	if _, err := runtime.Apply(context.Background(), changed); err != nil {
		t.Fatal(err)
	}
	roundTrip(t, proxyClient(t, changed.Config.Listeners[0].Port, "p2-password-a", target), "a moved")
	roundTrip(t, proxyClient(t, changed.Config.Listeners[1].Port, "p2-password-b", target), "b moved")
	changed.Config.Listeners[0].Enabled = false
	changed.Config.Listeners = changed.Config.Listeners[:1]
	if _, err := runtime.Apply(context.Background(), changed); err != nil {
		t.Fatal(err)
	}
	status := runtime.Snapshot()
	if len(status.Listeners) != 1 || status.Listeners[0].State != "disabled" {
		t.Fatalf("unexpected disabled status: %+v", status)
	}
	for _, spec := range input.Config.Listeners {
		listener, err := net.Listen("tcp", net.JoinHostPort(spec.Address, fmtPort(spec.Port)))
		if err != nil {
			t.Fatal("port not released", err)
		}
		listener.Close()
	}
}

func TestFailedListenerCanBeRecoveredWithoutRestartingPeers(t *testing.T) {
	target := echoTarget(t)
	input := realConfig(t)
	runtime := startReal(t, input)
	kept := proxyClient(t, input.Config.Listeners[1].Port, "p2-password-b", target)
	roundTrip(t, kept, "before")
	before := runtime.Snapshot()
	runtime.mu.RLock()
	instance := runtime.records["a"].instance
	runtime.mu.RUnlock()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := instance.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for listenerStatus(t, runtime, "a").State != "failed" {
		if time.Now().After(deadline) {
			t.Fatal("failure not observed")
		}
		time.Sleep(time.Millisecond)
	}
	if !runtime.Snapshot().Degraded {
		t.Fatal("failure hidden from status")
	}
	plan, err := runtime.Plan(input)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Changes[0].Action != "recover" {
		t.Fatalf("missing recovery action: %+v", plan)
	}
	result, err := runtime.Apply(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if result.Revision != before.Revision || runtime.Snapshot().Degraded {
		t.Fatal("recovery changed config revision or remained degraded")
	}
	roundTrip(t, kept, "after")
	roundTrip(t, proxyClient(t, input.Config.Listeners[0].Port, "p2-password-a", target), "recovered")
}

func TestInvalidReplacementDoesNotInterruptActiveListener(t *testing.T) {
	target := echoTarget(t)
	input := realConfig(t)
	runtime := startReal(t, input)
	conn := proxyClient(t, input.Config.Listeners[0].Port, "p2-password-a", target)
	roundTrip(t, conn, "before")
	before := listenerStatus(t, runtime, "a")
	changed := cloneConfig(t, input)
	changed.Config.Listeners[0].Options = json.RawMessage(`{"method":"invalid","secret":"do-not-print"}`)
	result, err := runtime.Apply(context.Background(), changed)
	if err == nil || result.Outcome != "rejected" || strings.Contains(err.Error(), "do-not-print") {
		t.Fatalf("bad rejection: %+v %v", result, err)
	}
	if listenerStatus(t, runtime, "a").Generation != before.Generation {
		t.Fatal("invalid config changed generation")
	}
	roundTrip(t, conn, "after")
}
