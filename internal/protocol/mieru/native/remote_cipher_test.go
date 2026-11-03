// SPDX-License-Identifier: GPL-3.0-only
package native

import (
	"net"
	"sync"
	"testing"
	"time"
)

func TestRemoteCipherUsersAndEpochsHaveIndependentLifetimes(t *testing.T) {
	prepared, err := PrepareUsers([]User{{Name: "alice", Password: "alice-pass"}, {Name: "bob", Password: "bob-pass"}})
	if err != nil {
		t.Fatal(err)
	}
	s := new(Server)
	peer := remoteKeyFrom(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1000})
	a, b := prepared.snapshot.users[0], prepared.snapshot.users[1]
	ak, _ := a.keysAt(time.Now())
	bk, _ := b.keysAt(time.Now())
	old := s.retainRemoteCipher(peer, userMatch{user: a, aead: ak.aead[0], epoch: ak.epoch - 120})
	current := s.retainRemoteCipher(peer, userMatch{user: a, aead: ak.aead[1], epoch: ak.epoch})
	bob := s.retainRemoteCipher(peer, userMatch{user: b, aead: bk.aead[1], epoch: bk.epoch})
	snapshot, _ := s.knownRemoteCiphers(peer)
	if len(snapshot) != 3 {
		t.Fatal("active user/epoch overwritten")
	}
	s.releaseRemoteCipher(current)
	s.rememberRemoteCipher(current)
	remaining, recent := s.knownRemoteCiphers(peer)
	if len(remaining) != 2 || recent == current || len(snapshot) != 3 {
		t.Fatal("release mutated old snapshot or restored closed epoch")
	}
	s.releaseRemoteCipher(old)
	remaining, _ = s.knownRemoteCiphers(peer)
	if len(remaining) != 1 || remaining[0] != bob {
		t.Fatal("Alice cleanup removed Bob")
	}
	s.releaseRemoteCipher(bob)
	remaining, _ = s.knownRemoteCiphers(peer)
	if len(remaining) != 0 {
		t.Fatal("last key leaked")
	}
}
func TestRemoteCipherConcurrentRetainRelease(t *testing.T) {
	prepared, _ := PrepareUsers([]User{{Name: "alice", Password: "alice-pass"}})
	user := prepared.snapshot.users[0]
	keys, _ := user.keysAt(time.Now())
	match := userMatch{user: user, aead: keys.aead[1], epoch: keys.epoch}
	s := new(Server)
	peer := packetRemoteKey{}
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				state := s.retainRemoteCipher(peer, match)
				s.rememberRemoteCipher(state)
				s.knownRemoteCiphers(peer)
				s.releaseRemoteCipher(state)
			}
		}()
	}
	wg.Wait()
	entries, _ := s.knownRemoteCiphers(peer)
	if len(entries) != 0 {
		t.Fatal("concurrent reference leaked")
	}
}
