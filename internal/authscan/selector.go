// SPDX-License-Identifier: GPL-3.0-only
package authscan

import (
	"errors"
	"sync"
)

var ErrNoMatch = errors.New("no authentication candidate matched")

// Selector belongs to one immutable credential snapshot. Replacing the
// snapshot creates a new selector, so indexes cannot outlive their credentials.
type Selector[K comparable] struct {
	cache *Cache[K]
	guard *Guard[K]
}

func NewSelector[K comparable](hash func(K) uint64, options GuardOptions) *Selector[K] {
	return &Selector[K]{cache: NewCache(hash), guard: NewGuard(hash, options)}
}

// Match is a tentative cryptographic match. Accept must only be called after
// complete authentication and replay checks. It holds no concurrency slot.
type Match[K comparable] struct {
	Index    int
	selector *Selector[K]
	key      K
	once     sync.Once
}

func (m *Match[K]) Accept() {
	if m == nil {
		return
	}
	m.once.Do(func() {
		m.selector.cache.Store(m.key, 1, uint32(m.Index))
		m.selector.guard.Reset(m.key)
	})
}

func (m *Match[K]) Reject() {
	if m == nil {
		return
	}
	m.once.Do(func() { m.selector.guard.Fail(m.key) })
}

// Find calls try only while holding a CPU permit. try must not perform I/O.
// A cached miss is inconclusive, allowing a different user behind the same NAT
// to fall back to the full scan without penalizing the source prematurely.
func (s *Selector[K]) Find(key K, count int, try func(int) bool) (*Match[K], error) {
	return s.FindPhased(key, count, try)
}

// FindPhased prioritizes cheap protocol hints before a compatibility fallback.
func (s *Selector[K]) FindPhased(key K, count int, tries ...func(int) bool) (*Match[K], error) {
	candidates, _ := s.cache.Load(key, 1)
	if candidates.Count() > 0 {
		permit, ok := s.guard.AcquireCached(key, candidates.Count()*len(tries))
		if !ok {
			return nil, ErrLimited
		}
		index := -1
		for _, try := range tries {
			for i := 0; i < candidates.Count(); i++ {
				candidate := int(candidates.At(i))
				if candidate < count && try(candidate) {
					index = candidate
					break
				}
			}
			if index >= 0 {
				break
			}
		}
		permit.Release()
		if index >= 0 {
			return &Match[K]{Index: index, selector: s, key: key}, nil
		}
	}
	remaining := count - candidates.Count()
	if remaining > 0 {
		permit, ok := s.guard.Acquire(key, remaining*len(tries))
		if !ok {
			return nil, ErrLimited
		}
		index := -1
		for _, try := range tries {
			for i := 0; i < count; i++ {
				if !candidates.Contains(uint32(i)) && try(i) {
					index = i
					break
				}
			}
			if index >= 0 {
				break
			}
		}
		permit.Release()
		if index >= 0 {
			return &Match[K]{Index: index, selector: s, key: key}, nil
		}
	}
	s.guard.Fail(key)
	return nil, ErrNoMatch
}

// CheckKnown meters an established session key without consuming scan backoff.
// A failure is inconclusive: the caller may fall back to credential discovery.
func (s *Selector[K]) CheckKnown(key K, work int, try func() bool) (bool, error) {
	permit, ok := s.guard.AcquireCached(key, work)
	if !ok {
		return false, ErrLimited
	}
	defer permit.Release()
	return try(), nil
}

// FindPrepared supports credential-dependent preamble lengths. prepare may read
// from the network but runs without a CPU permit. For cached=true it must only
// inspect already-buffered bytes: reading a longer cached user's header could
// otherwise deadlock a shorter valid handshake. Full indexes must be ordered by
// total required header length. The boolean says whether try should run.
func (s *Selector[K]) FindPrepared(key K, count int, prepare func(int, bool) (bool, error), try func(int) bool) (*Match[K], error) {
	candidates, _ := s.cache.Load(key, 1)
	attempted := make(map[int]bool, candidates.Count())
	for i := 0; i < candidates.Count(); i++ {
		index := int(candidates.At(i))
		ready, err := prepare(index, true)
		if err != nil {
			return nil, err
		}
		if !ready {
			continue
		}
		permit, ok := s.guard.AcquireCached(key, 1)
		if !ok {
			return nil, ErrLimited
		}
		matched := try(index)
		permit.Release()
		attempted[index] = true
		if matched {
			return &Match[K]{Index: index, selector: s, key: key}, nil
		}
	}
	lastCached := -1
	for i := 0; i < candidates.Count(); i++ {
		lastCached = max(lastCached, int(candidates.At(i)))
	}
	for index := 0; index < count; index++ {
		if attempted[index] {
			continue
		}
		// During backoff, public framing probes may advance only as far as a
		// cached candidate. They cannot authenticate an uncached user. This keeps
		// a long cached header reachable without blindly reading past a short one.
		if s.guard.blocked(key, s.guard.now()) && index > lastCached {
			return nil, ErrLimited
		}
		probePermit, ok := s.guard.AcquireCached(key, 1)
		if !ok {
			return nil, ErrLimited
		}
		probePermit.Release() // prepare may wait for more bytes
		ready, err := prepare(index, false)
		if err != nil {
			return nil, err
		}
		if !ready {
			continue
		}
		var permit *Permit[K]
		if candidates.Contains(uint32(index)) {
			permit, ok = s.guard.AcquireCached(key, 1)
		} else {
			permit, ok = s.guard.Acquire(key, 1)
		}
		if !ok {
			return nil, ErrLimited
		}
		matched := try(index)
		permit.Release()
		if matched {
			return &Match[K]{Index: index, selector: s, key: key}, nil
		}
	}
	if s.guard.blocked(key, s.guard.now()) {
		return nil, ErrLimited
	}
	s.guard.Fail(key)
	return nil, ErrNoMatch
}
