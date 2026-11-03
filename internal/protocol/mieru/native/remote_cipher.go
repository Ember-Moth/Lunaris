// SPDX-License-Identifier: GPL-3.0-only
package native

// An endpoint can carry several users and several still-live key epochs. Keep
// all of them until their last session closes; replacing a single endpoint key
// would break another user's session once that key leaves the discovery window.
type remoteCipherSet struct {
	entries []*remoteCipher
	recent  *remoteCipher
}

func (s *Server) knownRemoteCiphers(key packetRemoteKey) ([]*remoteCipher, *remoteCipher) {
	s.remoteCipherMu.Lock()
	defer s.remoteCipherMu.Unlock()
	set := s.remoteCiphers[key]
	if set == nil {
		return nil, nil
	}
	// Entries are immutable snapshots. Retain/release always allocate a new slice.
	return set.entries, set.recent
}
func (s *Server) rememberRemoteCipher(state *remoteCipher) {
	s.remoteCipherMu.Lock()
	defer s.remoteCipherMu.Unlock()
	if set := s.remoteCiphers[state.key]; set != nil && state.sessions > 0 {
		set.recent = state
	}
}
func (s *Server) retainRemoteCipher(key packetRemoteKey, match userMatch) *remoteCipher {
	s.remoteCipherMu.Lock()
	defer s.remoteCipherMu.Unlock()
	if s.remoteCiphers == nil {
		s.remoteCiphers = make(map[packetRemoteKey]*remoteCipherSet)
	}
	set := s.remoteCiphers[key]
	if set == nil {
		set = new(remoteCipherSet)
		s.remoteCiphers[key] = set
	}
	for _, state := range set.entries {
		if state.user.credential == match.user.credential && state.epoch == match.epoch {
			state.sessions++
			set.recent = state
			return state
		}
	}
	state := &remoteCipher{user: match.user, aead: match.aead, epoch: match.epoch, key: key, sessions: 1}
	set.entries = append(append([]*remoteCipher(nil), set.entries...), state)
	set.recent = state
	return state
}
func (s *Server) releaseRemoteCipher(state *remoteCipher) {
	s.remoteCipherMu.Lock()
	defer s.remoteCipherMu.Unlock()
	state.sessions--
	if state.sessions != 0 {
		return
	}
	set := s.remoteCiphers[state.key]
	if set == nil {
		return
	}
	entries := make([]*remoteCipher, 0, len(set.entries)-1)
	sameName := false
	for _, entry := range set.entries {
		if entry != state {
			entries = append(entries, entry)
			sameName = sameName || entry.user.name == state.user.name
		}
	}
	set.entries = entries
	if set.recent == state {
		set.recent = nil
	}
	if len(entries) == 0 {
		delete(s.remoteCiphers, state.key)
	}
	if !sameName {
		s.nonceApplied.Delete(packetNonceKey{remote: state.key, user: state.user.name})
	}
}
