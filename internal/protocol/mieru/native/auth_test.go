// SPDX-License-Identifier: GPL-3.0-only
package native

import (
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/authscan"
)

type countedAEAD struct {
	cipherAEAD
	calls *int
}

func (c countedAEAD) Open(dst, nonce, text, aad []byte) ([]byte, error) {
	*c.calls++
	return c.cipherAEAD.Open(dst, nonce, text, aad)
}
func TestDiscoverFallbackCacheAndCredentialRotation(t *testing.T) {
	users := make([]User, 16)
	for i := range users {
		users[i] = User{Name: fmt.Sprintf("user-%02d", i), Password: fmt.Sprintf("secret-%02d", i)}
	}
	prepared, err := PrepareUsers(users)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := prepared.snapshot
	target := snapshot.users[15]
	calls := 0
	for _, u := range snapshot.users {
		keys, _ := u.keysAt(time.Now())
		for i := range keys.aead {
			keys.aead[i] = countedAEAD{keys.aead[i], &calls}
		}
	}
	keys, _ := target.keysAt(time.Now())
	// A valid client without a recognized username hint must still authenticate.
	packet, err := sealPacket(nil, metadata{protocol: openSessionRequest, sessionID: 1}, nil, keys.aead[1], "unrecognized-hint")
	if err != nil {
		t.Fatal(err)
	}
	source := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1000}
	discover := func() (userMatch, error) {
		return snapshot.discover(packet[:packetHeaderSize], make([]byte, 0, metadataLength), source)
	}
	m, err := discover()
	if err != nil || m.user != target {
		t.Fatal(err)
	}
	cold := calls
	calls = 0
	m, err = discover()
	if err != nil || calls != cold {
		t.Fatal("tentative match cached", calls, cold, err)
	}
	m.verdict.Accept()
	calls = 0
	m, err = discover()
	if err != nil || calls != 2 {
		t.Fatal("warm user still scanned list", calls, err)
	}
	m.verdict.Reject()
	calls = 0
	if _, err = discover(); err != nil || calls != 2 {
		t.Fatal("known candidate blocked", calls, err)
	}
	users[15].Password = "rotated-password"
	next, err := PrepareUsers(users)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = next.snapshot.discover(packet[:packetHeaderSize], make([]byte, 0, metadataLength), source); !errors.Is(err, authscan.ErrNoMatch) {
		t.Fatal("removed credential survived new snapshot", err)
	}
}

func TestPacketMalformedPayloadDoesNotWarmAuthentication(t *testing.T) {
	prepared, err := PrepareUsers([]User{{Name: "alice", Password: "password"}})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{}
	s.users.Store(prepared.snapshot)
	keys, _ := prepared.snapshot.users[0].keysAt(time.Now())
	packet, err := sealPacket(nil, metadata{protocol: openSessionRequest, sessionID: 1}, []byte("payload"), keys.aead[1], "alice")
	if err != nil {
		t.Fatal(err)
	}
	packet[len(packet)-1] ^= 1
	source := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1000}
	if _, _, err = s.parsePacket(packet, source); err == nil {
		t.Fatal("invalid payload accepted")
	}
	if _, err = prepared.snapshot.discover(packet[:packetHeaderSize], make([]byte, 0, metadataLength), source); !errors.Is(err, authscan.ErrLimited) {
		t.Fatal("invalid payload warmed/reset source", err)
	}
}
