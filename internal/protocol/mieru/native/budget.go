// SPDX-License-Identifier: GPL-3.0-only
package native

import "context"

const maxBufferedPayload = 64 << 20

func (s *Server) reserveBytes(n int) bool {
	if n == 0 {
		return true
	}
	s.budgetMu.Lock()
	defer s.budgetMu.Unlock()
	if s.buffered+int64(n) > maxBufferedPayload {
		return false
	}
	s.buffered += int64(n)
	return true
}
func (s *Server) waitBytes(ctx context.Context, n int) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	if n == 0 {
		return ctx.Err() == nil
	}
	for {
		s.budgetMu.Lock()
		if ctx.Err() != nil {
			s.budgetMu.Unlock()
			return false
		}
		if s.buffered+int64(n) <= maxBufferedPayload {
			s.buffered += int64(n)
			s.budgetMu.Unlock()
			return true
		}
		if s.budgetChanged == nil {
			s.budgetChanged = make(chan struct{})
		}
		changed := s.budgetChanged
		s.budgetMu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return false
		}
	}
}
func (s *Server) releaseBytes(n int) {
	if n == 0 {
		return
	}
	s.budgetMu.Lock()
	s.buffered -= int64(n)
	if s.budgetChanged != nil {
		close(s.budgetChanged)
		s.budgetChanged = nil
	}
	s.budgetMu.Unlock()
}
