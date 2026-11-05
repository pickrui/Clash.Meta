package adapter

import (
	"sync"
	"sync/atomic"

	C "github.com/metacubex/mihomo/constant"
)

type proxyStateEntry struct {
	url   string
	state *internalProxyState
}

type proxyStates struct {
	first atomic.Pointer[proxyStateEntry]
	mu    sync.RWMutex
	other map[string]*internalProxyState
}

func (s *proxyStates) Load(url string) (*internalProxyState, bool) {
	first := s.first.Load()
	if first == nil {
		return nil, false
	}
	if first.url == url {
		return first.state, true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, ok := s.other[url]
	return state, ok
}

func (s *proxyStates) LoadOrStoreFn(url string, makeState func() *internalProxyState) (*internalProxyState, bool) {
	if state, ok := s.Load(url); ok {
		return state, true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	first := s.first.Load()
	if first == nil {
		state := makeState()
		s.first.Store(&proxyStateEntry{url: url, state: state})
		return state, false
	}
	if first.url == url {
		return first.state, true
	}
	if state, ok := s.other[url]; ok {
		return state, true
	}
	if s.other == nil {
		s.other = make(map[string]*internalProxyState)
	}
	state := makeState()
	s.other[url] = state
	return state, false
}

func (s *proxyStates) Range(f func(string, *internalProxyState) bool) {
	first := s.first.Load()
	if first == nil || !f(first.url, first.state) {
		return
	}
	s.mu.RLock()
	snapshot := make([]proxyStateEntry, 0, len(s.other))
	for url, state := range s.other {
		snapshot = append(snapshot, proxyStateEntry{url: url, state: state})
	}
	s.mu.RUnlock()
	for _, entry := range snapshot {
		if !f(entry.url, entry.state) {
			return
		}
	}
}

type delayHistory struct {
	buffer atomic.Pointer[delayHistoryBuffer]
}

type delayHistoryBuffer struct {
	mu    sync.RWMutex
	items [defaultHistoriesNum]C.DelayHistory
	next  uint8
	size  uint8
}

func (h *delayHistory) Put(record C.DelayHistory) {
	buffer := h.buffer.Load()
	if buffer == nil {
		h.buffer.CompareAndSwap(nil, new(delayHistoryBuffer))
		buffer = h.buffer.Load()
	}
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	buffer.items[buffer.next] = record
	buffer.next = (buffer.next + 1) % defaultHistoriesNum
	if buffer.size < defaultHistoriesNum {
		buffer.size++
	}
}

func (h *delayHistory) Last() C.DelayHistory {
	buffer := h.buffer.Load()
	if buffer == nil {
		return C.DelayHistory{}
	}
	buffer.mu.RLock()
	defer buffer.mu.RUnlock()
	return buffer.items[(buffer.next+defaultHistoriesNum-1)%defaultHistoriesNum]
}

func (h *delayHistory) Copy() []C.DelayHistory {
	buffer := h.buffer.Load()
	if buffer == nil {
		return nil
	}
	buffer.mu.RLock()
	defer buffer.mu.RUnlock()
	if buffer.size == 0 {
		return nil
	}
	items := make([]C.DelayHistory, buffer.size)
	start := (int(buffer.next) - len(items) + defaultHistoriesNum) % defaultHistoriesNum
	n := copy(items, buffer.items[start:])
	copy(items[n:], buffer.items[:buffer.next])
	return items
}
