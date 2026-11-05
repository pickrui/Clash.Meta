package singledo

import "time"

func (s *Single[T]) Forget(stale func(T) bool) {
	s.ForgetAfter(0, stale)
}

// ForgetAfter drops a finished result at least age old when stale rejects it.
// A younger result or a call in flight stays shared.
func (s *Single[T]) ForgetAfter(age time.Duration, stale func(T) bool) {
	s.mux.Lock()
	defer s.mux.Unlock()
	if s.result != nil && time.Since(s.result.Time) >= age && stale(s.result.Val) {
		s.result = nil
	}
}
