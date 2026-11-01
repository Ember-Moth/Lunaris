// SPDX-License-Identifier: GPL-3.0-only
package node

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/testutil"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

func TestCertificateRotationRevokesOnlyAffectedListener(t *testing.T) {
	const id = "c8820ed3-e4ee-47ad-a5bd-ece70763e32c"
	a, trustA := testutil.Certificate(t)
	b, trustB := testutil.Certificate(t)
	next, trustNext := testutil.Certificate(t)
	input := realConfig(t)
	input.Credentials = map[string][]byte{"a": []byte(id), "b": []byte(id)}
	input.Certificates = map[string]model.Certificate{"a": a, "b": b}
	for i := range input.Config.Listeners {
		s := &input.Config.Listeners[i]
		s.Protocol = "vless"
		s.CertificateRef = s.ID
		s.Options = []byte("{}")
		s.Network = []string{"tcp"}
	}
	runtime := startReal(t, input)
	target := M.SocksaddrFromNet(testutil.TCPEcho(t))
	connect := func(index int, trust *tls.Config) net.Conn {
		t.Helper()
		s := input.Config.Listeners[index]
		raw, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", fmt.Sprintf("127.0.0.1:%d", s.Port), trust)
		if err != nil {
			t.Fatal(err)
		}
		client, _ := vless.NewClient(id, "", logger.NOP())
		c, err := client.DialConn(raw, target)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	roundtrip := func(c net.Conn) {
		t.Helper()
		_ = c.SetDeadline(time.Now().Add(time.Second))
		payload := []byte("certificate rotation")
		if _, err := c.Write(payload); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, len(payload))
		if _, err := io.ReadFull(c, b); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(b, payload) {
			t.Fatal("payload changed")
		}
	}
	heldA, heldB := connect(0, trustA), connect(1, trustB)
	roundtrip(heldA)
	roundtrip(heldB)
	beforeB := listenerStatus(t, runtime, "b").Generation
	changed := cloneConfig(t, input)
	changed.Certificates["a"] = next
	plan, err := runtime.Plan(changed)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Changes) != 2 || plan.Changes[0].Action != "replace" || plan.Changes[1].Action != "keep" {
		t.Fatalf("certificate plan: %+v", plan)
	}
	if _, err = runtime.Apply(context.Background(), changed); err != nil {
		t.Fatal(err)
	}
	_ = heldA.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = heldA.Read(make([]byte, 1)); err == nil {
		t.Fatal("old TLS stream survived rotation")
	}
	roundtrip(heldB)
	if listenerStatus(t, runtime, "b").Generation != beforeB {
		t.Fatal("unaffected listener rebuilt")
	}
	roundtrip(connect(0, trustNext))
	old, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", fmt.Sprintf("127.0.0.1:%d", input.Config.Listeners[0].Port), trustA)
	if err == nil {
		old.Close()
		t.Fatal("old certificate still served")
	}
}
