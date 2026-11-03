// SPDX-License-Identifier: GPL-3.0-only
package vmess

import (
	"bytes"
	"context"
	"errors"
	"github.com/Ember-Moth/Lunaris/internal/authscan"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	upstream "github.com/sagernet/sing-vmess"
	M "github.com/sagernet/sing/common/metadata"
	"testing"
	"time"
)

func TestFutureAuthIDReplayAfterUpstreamWindow(t *testing.T) {
	id := "7d27b49e-3b7b-45dc-8308-f0c15c152bde"
	h := new(recordingHandler)
	s, err := newServer(protocol.ResolvedListenerSpec{Spec: model.ListenerSpec{CredentialRefs: []string{"alice"}}, Credentials: map[string][]byte{"alice": []byte(id)}}, h)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	now := started
	s.now = func() time.Time { return now }
	s.replay = authscan.NewReplayWindow[replayKey](4, replayLifetime, s.now)
	issued := now.Add(120 * time.Second)
	client, err := upstream.NewClient(id, "aes-128-gcm", 0, upstream.ClientWithTimeFunc(func() time.Time { return issued }))
	if err != nil {
		t.Fatal(err)
	}
	wire := new(memoryConn)
	conn, err := client.DialConn(wire, M.ParseSocksaddr("127.0.0.1:80"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Write([]byte("replay-window")); err != nil {
		t.Fatal(err)
	}
	packet := bytes.Clone(wire.Bytes())
	serve := func() error {
		return s.serve(context.Background(), &memoryConn{input: bytes.NewReader(packet)}, M.ParseSocksaddr("127.0.0.1:1000"), nil)
	}
	if err = serve(); err != nil {
		t.Fatal("initial request", err)
	}
	for _, elapsed := range []time.Duration{0, 121 * time.Second, 240 * time.Second} {
		now = started.Add(elapsed)
		// The window's clock follows the server without sleeping in the test suite.
		// Distinguish our error from upstream.ErrReplay: upstream wall time has not
		// advanced, so its old filter would otherwise hide a missing outer check.
		if err = serve(); !errors.Is(err, errAuthReplay) {
			t.Fatalf("elapsed %s: outer replay guard did not reject: %v", elapsed, err)
		}
	}
	if len(h.users) != 1 {
		t.Fatal("request relayed repeatedly", h.users)
	}
}
func TestVMessReplayIdentitySeparatesUsers(t *testing.T) {
	window := authscan.NewReplayWindow[replayKey](4, replayLifetime, nil)
	id := [16]byte{1, 2, 3}
	if !window.Accept(replayKey{user: 0, id: id}) || !window.Accept(replayKey{user: 1, id: id}) || window.Accept(replayKey{user: 0, id: id}) {
		t.Fatal("user replay identities collided")
	}
}
