// SPDX-License-Identifier: GPL-3.0-only
package authscan

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestSelectorCacheRequiresCompleteAuthentication(t *testing.T) {
	now := time.Unix(100, 0)
	s := NewSelector(func(x int) uint64 { return uint64(x) }, GuardOptions{WorkRate: 10000, Concurrent: 1, TimeFunc: func() time.Time { return now }})
	attempts := 0
	try := func(index int) bool { attempts++; return index == 99 }
	match, err := s.Find(1, 100, try)
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 100 {
		t.Fatal(attempts)
	}
	// A tentative match releases its CPU slot but never fills the candidate cache.
	if _, ok := s.cache.Load(1, 1); ok {
		t.Fatal("tentative key cached")
	}
	match2, err := s.Find(2, 100, try)
	if err != nil {
		t.Fatal("handshake held CPU slot", err)
	}
	match2.Reject()
	match2.Accept()
	if _, ok := s.cache.Load(2, 1); ok {
		t.Fatal("rejected key cached")
	}
	match.Accept()
	attempts = 0
	if _, err = s.Find(1, 100, try); err != nil || attempts != 1 {
		t.Fatal("warm scan", attempts, err)
	}
	// A failed user behind the same source may block cold scans, but a known
	// candidate still gets a cryptographic check under the global budget.
	if _, err = s.Find(1, 100, func(int) bool { return false }); !errors.Is(err, ErrNoMatch) {
		t.Fatal(err)
	}
	attempts = 0
	if _, err = s.Find(1, 100, try); err != nil || attempts != 1 {
		t.Fatal("NAT cache", attempts, err)
	}
	if _, err = s.Find(1, 100, func(int) bool { return false }); !errors.Is(err, ErrLimited) {
		t.Fatal("source backoff", err)
	}
}

func TestSelectorCachedTrafficStillConsumesBudget(t *testing.T) {
	now := time.Unix(100, 0)
	s := NewSelector(func(x int) uint64 { return uint64(x) }, GuardOptions{WorkRate: 2, WorkBurst: 2, TimeFunc: func() time.Time { return now }})
	m, err := s.Find(1, 1, func(int) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	m.Accept()
	if _, err = s.Find(1, 1, func(int) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Find(1, 1, func(int) bool { t.Fatal("unmetered cached call"); return true }); !errors.Is(err, ErrLimited) {
		t.Fatal(err)
	}
	if p, ok := s.guard.Acquire(2, 3); ok {
		p.Release()
		t.Fatal("oversized work granted")
	}
}

func TestPreparedScanDoesNotHoldSlotAcrossReads(t *testing.T) {
	s := NewSelector(func(x int) uint64 { return uint64(x) }, GuardOptions{Concurrent: 1})
	entered, release := make(chan struct{}), make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := s.FindPrepared(1, 1, func(int, bool) (bool, error) { close(entered); <-release; return true, nil }, func(int) bool { return true })
		if err != nil {
			t.Error(err)
		}
	}()
	<-entered
	if _, err := s.Find(2, 1, func(int) bool { return true }); err != nil {
		t.Error("network read held CPU permit", err)
	}
	close(release)
	wg.Wait()
}

func TestSelectorSnapshotReplacementCannotReuseIndexes(t *testing.T) {
	hash := func(x int) uint64 { return uint64(x) }
	old := NewSelector(hash, GuardOptions{})
	m, _ := old.Find(1, 2, func(i int) bool { return i == 1 })
	current := NewSelector(hash, GuardOptions{})
	m.Accept()
	count := 0
	if _, err := current.Find(1, 2, func(i int) bool { count++; return i == 1 }); err != nil || count != 2 {
		t.Fatal(count, err)
	}
}

func TestPreparedBackoffKeepsOnlyCachedCryptographicAttempts(t *testing.T) {
	now := time.Unix(100, 0)
	s := NewSelector(func(x int) uint64 { return uint64(x) }, GuardOptions{WorkBurst: 100, TimeFunc: func() time.Time { return now }})
	m, _ := s.Find(1, 3, func(i int) bool { return i == 2 })
	m.Accept()
	s.guard.Fail(1)
	var probes, attempts []int
	_, err := s.FindPrepared(1, 3, func(i int, cached bool) (bool, error) {
		if cached {
			return false, nil
		}
		probes = append(probes, i)
		return i == 2, nil
	}, func(i int) bool { attempts = append(attempts, i); return true })
	if err != nil || len(probes) != 3 || len(attempts) != 1 || attempts[0] != 2 {
		t.Fatal("cached deferred attempt", probes, attempts, err)
	}
	// Even the limited public-probe path must stop when its work budget is gone.
	s.guard.budget.Lock()
	s.guard.tokens = 0
	s.guard.budget.Unlock()
	if _, err = s.FindPrepared(1, 3, func(_ int, cached bool) (bool, error) {
		if !cached {
			t.Fatal("unmetered framing probe")
		}
		return false, nil
	}, func(int) bool { t.Fatal("unmetered crypto"); return true }); err != ErrLimited {
		t.Fatal(err)
	}
}
