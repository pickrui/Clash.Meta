package provider

import (
	"context"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	C "github.com/metacubex/mihomo/constant"
	"golang.org/x/sync/semaphore"
)

const backgroundHealthCheckLimit = 10

var (
	healthCheckSuspended   = atomic.NewBool(false)
	backgroundHealthChecks = newHealthCheckSchedule()
	healthCheckPriority    atomic.TypedValue[func() map[string]struct{}]
)

type healthCheckSchedule struct {
	mu      sync.Mutex
	paused  bool
	ctx     context.Context
	cancel  context.CancelFunc
	changed chan struct{}
	slots   *semaphore.Weighted
}

func newHealthCheckSchedule() *healthCheckSchedule {
	ctx, cancel := context.WithCancel(context.Background())
	return &healthCheckSchedule{ctx: ctx, cancel: cancel, changed: make(chan struct{}), slots: semaphore.NewWeighted(backgroundHealthCheckLimit)}
}

func (s *healthCheckSchedule) setPaused(paused bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.paused == paused {
		return
	}
	s.paused = paused
	if paused {
		s.cancel()
	} else {
		s.ctx, s.cancel = context.WithCancel(context.Background())
	}
	close(s.changed)
	s.changed = make(chan struct{})
}

func (s *healthCheckSchedule) state() (bool, context.Context, <-chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.paused, s.ctx, s.changed
}

func SetHealthCheckState(idle, suspended bool) {
	healthCheckSuspended.Store(suspended)
	backgroundHealthChecks.setPaused(idle || suspended)
}

func BackgroundHealthChecksPaused() bool {
	paused, _, _ := backgroundHealthChecks.state()
	return paused
}

func SetHealthCheckPriority(priority func() map[string]struct{}) {
	healthCheckPriority.Store(priority)
}

func prioritizeHealthChecks(proxies []C.Proxy, url string, selected map[string]struct{}) []C.Proxy {
	var buckets [3][]C.Proxy
	for _, proxy := range proxies {
		priority := 2
		if _, chosen := selected[proxy.Name()]; chosen {
			priority = 0
		} else if !proxy.AliveForTestUrl(url) {
			priority = 1
		}
		buckets[priority] = append(buckets[priority], proxy)
	}
	ordered := make([]C.Proxy, 0, len(proxies))
	for _, bucket := range buckets {
		ordered = append(ordered, bucket...)
	}
	return ordered
}

func measuredInHealthCheckRound(proxy C.Proxy, url, expected string, timeout time.Duration, began time.Time) bool {
	reader, ok := proxy.(interface {
		URLTestSucceededSince(string, string, time.Duration, time.Time) bool
	})
	return ok && reader.URLTestSucceededSince(url, expected, timeout, began)
}
