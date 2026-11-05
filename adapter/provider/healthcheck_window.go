package provider

import (
	"cmp"
	"container/heap"
	"context"
	"slices"

	C "github.com/metacubex/mihomo/constant"

	"github.com/dlclark/regexp2"
)

const (
	healthCheckWindowSize     = 1000
	healthCheckWindowPriority = healthCheckWindowSize / 2
	healthCheckBestKnown      = 64
)

func (hc *HealthCheck) window(ctx context.Context, proxies []C.Proxy, url string, filter *regexp2.Regexp, selected map[string]struct{}) ([]C.Proxy, int, error) {
	hc.windowMu.Lock()
	start := hc.windowNext[url] % len(proxies)
	hc.windowMu.Unlock()

	indices := make([]int, 0, healthCheckWindowSize)
	taken := make(map[int]struct{}, healthCheckWindowSize)
	take := func(i, limit int) {
		if _, exists := taken[i]; !exists && len(indices) < limit {
			taken[i] = struct{}{}
			indices = append(indices, i)
		}
	}
	matches := func(i int) (bool, error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if filter != nil {
			return filter.MatchString(proxies[i].Name())
		}
		return true, nil
	}
	failed := make([]int, 0, healthCheckWindowPriority)
	best := make(healthCheckCandidates, 0, healthCheckBestKnown)
	for walked := range len(proxies) {
		if err := ctx.Err(); err != nil {
			return nil, -1, err
		}
		i := (start + walked) % len(proxies)
		proxy := proxies[i]
		_, chosen := selected[proxy.Name()]
		chosen = chosen && len(indices) < healthCheckWindowPriority
		alive := proxy.AliveForTestUrl(url)
		wantFailed := !alive && len(failed) < healthCheckWindowPriority
		candidate := healthCheckCandidate{index: i}
		if alive {
			candidate.delay = proxy.LastDelayForTestUrl(url)
		}
		wantBest := candidate.delay > 0 && candidate.delay < 0xffff &&
			(len(best) < healthCheckBestKnown || candidate.compare(best[0]) < 0)
		if !chosen && !wantFailed && !wantBest {
			continue
		}
		match, err := matches(i)
		if err != nil {
			return nil, -1, err
		}
		if !match {
			continue
		}
		if chosen {
			take(i, healthCheckWindowPriority)
		}
		if wantFailed {
			failed = append(failed, i)
		}
		if wantBest {
			if len(best) < healthCheckBestKnown {
				heap.Push(&best, candidate)
			} else {
				best[0] = candidate
				heap.Fix(&best, 0)
			}
		}
	}
	slices.SortFunc(best, healthCheckCandidate.compare)
	for _, candidate := range best {
		take(candidate.index, healthCheckWindowPriority)
	}
	for _, i := range failed {
		take(i, healthCheckWindowPriority)
	}

	// Reserve at least half the window for rotation so priority nodes cannot starve the rest.
	walked := 0
	for walked < len(proxies) && len(indices) < healthCheckWindowSize {
		i := (start + walked) % len(proxies)
		walked++
		if _, exists := taken[i]; exists {
			continue
		}
		match, err := matches(i)
		if err != nil {
			return nil, -1, err
		}
		if match {
			take(i, healthCheckWindowSize)
		}
	}
	window := make([]C.Proxy, len(indices))
	for i, index := range indices {
		window[i] = proxies[index]
	}
	return window, (start + walked) % len(proxies), nil
}

type healthCheckCandidate struct {
	index int
	delay uint16
}

func (a healthCheckCandidate) compare(b healthCheckCandidate) int {
	if order := cmp.Compare(a.delay, b.delay); order != 0 {
		return order
	}
	return cmp.Compare(a.index, b.index)
}

type healthCheckCandidates []healthCheckCandidate

func (h healthCheckCandidates) Len() int           { return len(h) }
func (h healthCheckCandidates) Less(i, j int) bool { return h[i].compare(h[j]) > 0 }
func (h healthCheckCandidates) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *healthCheckCandidates) Push(x any)        { *h = append(*h, x.(healthCheckCandidate)) }
func (h *healthCheckCandidates) Pop() any {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]
	return x
}
