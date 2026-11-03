// SPDX-License-Identifier: GPL-3.0-only
package native5

import "testing"

func TestSharedReplayFilterSeparatesCredentials(t *testing.T) {
	cache := new(SaltReplayCache)
	first, err := NewService(ServiceOptions{PSK: []byte("first-password"), ReplayCache: cache})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewService(ServiceOptions{PSK: []byte("second-password"), ReplayCache: cache})
	if err != nil {
		t.Fatal(err)
	}
	salt := []byte("0123456789abcdef")
	if first.replayedSalt(salt) {
		t.Fatal("fresh salt rejected")
	}
	if !first.replayedSalt(salt) {
		t.Fatal("replay accepted")
	}
	if second.replayedSalt(salt) {
		t.Fatal("different credential collided")
	}
	if !second.replayedSalt(salt) {
		t.Fatal("second replay accepted")
	}
	if first.saltCache != second.saltCache || cache.counts[0] != 2 {
		t.Fatal("per-user replay filter allocated")
	}
}
