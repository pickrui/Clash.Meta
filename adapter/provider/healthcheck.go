package provider

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/singledo"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/dlclark/regexp2"
	"golang.org/x/sync/errgroup"
)

type HealthCheckOption struct {
	URL      string
	Interval uint
}

type extraOption struct {
	expectedStatus utils.IntRanges[uint16]
	filters        map[string]struct{}
}

type healthCheckMode uint8

const (
	healthCheckManual healthCheckMode = iota
	healthCheckScheduled
	healthCheckRecovery
)

type HealthCheck struct {
	ctx            context.Context
	ctxCancel      context.CancelFunc
	url            string
	extra          map[string]*extraOption
	mu             sync.Mutex
	proxies        []C.Proxy
	interval       time.Duration
	lazy           bool
	expectedStatus utils.IntRanges[uint16]
	lastTouch      atomic.TypedValue[time.Time]
	singleDo       *singledo.Single[struct{}]
	scheduledDo    *singledo.Single[struct{}]
	recoveryDo     *singledo.Single[struct{}]
	timeout        time.Duration
	windowMu       sync.Mutex
	windowNext     map[string]int
}

func (hc *HealthCheck) process() {
	var ticker *time.Ticker
	var ticks <-chan time.Time
	defer func() {
		if ticker != nil {
			ticker.Stop()
		}
	}()
	go hc.checkScheduled()
	for {
		paused, _, changed := backgroundHealthChecks.state()
		if paused && ticker != nil {
			ticker.Stop()
			ticker, ticks = nil, nil
		} else if !paused && ticker == nil {
			ticker = time.NewTicker(hc.interval)
			ticks = ticker.C
		}
		select {
		case <-changed:
			if ticker != nil {
				ticker.Stop()
				ticker, ticks = nil, nil
			}
		case <-ticks:
			lastTouch := hc.lastTouch.Load()
			since := time.Since(lastTouch)
			if !hc.lazy || since < hc.interval {
				hc.checkScheduled()
			} else {
				log.Debugln("Skip once health check because we are lazy")
			}
		case <-hc.ctx.Done():
			return
		}
	}
}

func (hc *HealthCheck) setProxies(proxies []C.Proxy) {
	hc.mu.Lock()
	hc.proxies = append([]C.Proxy(nil), proxies...)
	hc.mu.Unlock()
}

func (hc *HealthCheck) registerHealthCheckTask(url string, expectedStatus utils.IntRanges[uint16], filter string, interval uint) {
	url = strings.TrimSpace(url)
	if len(url) == 0 || url == hc.url {
		log.Debugln("ignore invalid health check url: %s", url)
		return
	}

	hc.mu.Lock()
	defer hc.mu.Unlock()

	// if the provider has not set up health checks, then modify it to be the same as the group's interval
	if hc.interval == 0 {
		hc.interval = time.Duration(interval) * time.Second
	}

	if hc.extra == nil {
		hc.extra = make(map[string]*extraOption)
	}

	// prioritize the use of previously registered configurations, especially those from provider
	if _, ok := hc.extra[url]; ok {
		// provider default health check does not set filter
		if url != hc.url && len(filter) != 0 {
			splitAndAddFiltersToExtra(filter, hc.extra[url])
		}

		log.Debugln("health check url: %s exists", url)
		return
	}

	option := &extraOption{filters: map[string]struct{}{}, expectedStatus: expectedStatus}
	splitAndAddFiltersToExtra(filter, option)
	hc.extra[url] = option
}

func splitAndAddFiltersToExtra(filter string, option *extraOption) {
	filter = strings.TrimSpace(filter)
	if len(filter) != 0 {
		for _, regex := range strings.Split(filter, "`") {
			regex = strings.TrimSpace(regex)
			if len(regex) != 0 {
				option.filters[regex] = struct{}{}
			}
		}
	}
}

func (hc *HealthCheck) auto() bool {
	return hc.interval != 0
}

func (hc *HealthCheck) touch() {
	hc.lastTouch.Store(time.Now())
}

func (hc *HealthCheck) check() {
	hc.checkWithContext(hc.ctx, healthCheckManual)
}

func (hc *HealthCheck) checkScheduled() {
	hc.checkBackground(healthCheckScheduled)
}

func (hc *HealthCheck) checkBackground(mode healthCheckMode) {
	paused, active, _ := backgroundHealthChecks.state()
	if paused || active.Err() != nil {
		return
	}
	ctx, cancel := context.WithCancel(hc.ctx)
	stop := context.AfterFunc(active, cancel)
	defer stop()
	defer cancel()
	if active.Err() != nil {
		return
	}
	hc.checkWithContext(adapter.WithBackgroundURLTest(ctx), mode)
}

func (hc *HealthCheck) checkWithContext(ctx context.Context, mode healthCheckMode) {
	if healthCheckSuspended.Load() || ctx.Err() != nil {
		return
	}
	hc.mu.Lock()
	empty := len(hc.proxies) == 0
	hc.mu.Unlock()
	if empty {
		return
	}
	singleDo := hc.singleDo
	switch mode {
	case healthCheckScheduled:
		singleDo = hc.scheduledDo
	case healthCheckRecovery:
		singleDo = hc.recoveryDo
	}
	_, _, _ = singleDo.Do(func() (struct{}, error) {
		if healthCheckSuspended.Load() || ctx.Err() != nil {
			return struct{}{}, nil
		}
		hc.mu.Lock()
		// Constructor and replacement own their slices; published slices stay immutable.
		proxies := hc.proxies
		extra := make(map[string]*extraOption, len(hc.extra))
		for url, option := range hc.extra {
			filters := make(map[string]struct{}, len(option.filters))
			for filter := range option.filters {
				filters[filter] = struct{}{}
			}
			extra[url] = &extraOption{
				expectedStatus: option.expectedStatus,
				filters:        filters,
			}
		}
		url := hc.url
		expectedStatus := hc.expectedStatus
		hc.mu.Unlock()
		if len(proxies) == 0 {
			return struct{}{}, nil
		}
		id := utils.NewUUIDV4().String()
		log.Debugln("Start New Health Checking {%s}", id)
		b := new(errgroup.Group)
		b.SetLimit(10)
		began := time.Now()
		var selected map[string]struct{}
		if priority := healthCheckPriority.Load(); mode != healthCheckManual && priority != nil {
			selected = priority()
		}
		nextWindows := make(map[string]int)
		execute := func(url string, option *extraOption) {
			if next := hc.execute(ctx, b, proxies, url, id, option, mode, began, selected); next >= 0 {
				nextWindows[strings.TrimSpace(url)] = next
			}
		}

		// execute default health check
		option := &extraOption{filters: nil, expectedStatus: expectedStatus}
		execute(url, option)

		// execute extra health check
		if len(extra) != 0 {
			for url, option := range extra {
				execute(url, option)
			}
		}
		_ = b.Wait()
		if ctx.Err() == nil && len(nextWindows) != 0 {
			hc.windowMu.Lock()
			if hc.windowNext == nil {
				hc.windowNext = make(map[string]int)
			}
			for url, next := range nextWindows {
				hc.windowNext[url] = next
			}
			hc.windowMu.Unlock()
		}
		log.Debugln("Finish A Health Checking {%s}", id)
		return struct{}{}, nil
	})
}

func (hc *HealthCheck) execute(ctx context.Context, b *errgroup.Group, proxies []C.Proxy, url, uid string, option *extraOption, mode healthCheckMode, began time.Time, selected map[string]struct{}) int {
	if ctx.Err() != nil {
		return -1
	}
	url = strings.TrimSpace(url)
	if len(url) == 0 {
		log.Debugln("Health Check has been skipped due to testUrl is empty, {%s}", uid)
		return -1
	}

	var filterReg *regexp2.Regexp
	var expectedStatus utils.IntRanges[uint16]
	if option != nil {
		expectedStatus = option.expectedStatus
		if len(option.filters) != 0 {
			filters := make([]string, 0, len(option.filters))
			for filter := range option.filters {
				filters = append(filters, filter)
			}

			var err error
			filterReg, err = utils.CompileNameRegex(strings.Join(filters, "|"))
			if err != nil {
				log.Errorln("Health check filter is invalid: %v", err)
				return -1
			}
		}
	}

	background := mode != healthCheckManual
	nextWindow := -1
	if mode == healthCheckScheduled && len(proxies) > healthCheckWindowSize {
		var err error
		proxies, nextWindow, err = hc.window(ctx, proxies, url, filterReg, selected)
		if err != nil {
			if ctx.Err() == nil {
				log.Errorln("Health check filter evaluation failed: %v", err)
			}
			return -1
		}
		filterReg = nil
	}
	if background {
		proxies = prioritizeHealthChecks(proxies, url, selected)
	}
	expected := expectedStatus.String()
	for _, proxy := range proxies {
		if ctx.Err() != nil {
			return -1
		}
		// skip proxies that do not require health check
		if filterReg != nil {
			match, err := filterReg.MatchString(proxy.Name())
			if err != nil {
				log.Errorln("Health check filter evaluation failed: %v", err)
				return -1
			}
			if !match {
				continue
			}
		}

		p := proxy
		if background {
			if err := backgroundHealthChecks.slots.Acquire(ctx, 1); err != nil {
				return -1
			}
			if ctx.Err() != nil || measuredInHealthCheckRound(p, url, expected, hc.timeout, began) {
				backgroundHealthChecks.slots.Release(1)
				continue
			}
		}
		b.Go(func() error {
			if background {
				defer backgroundHealthChecks.slots.Release(1)
			}
			if ctx.Err() != nil {
				return nil
			}
			// Queueing is outside the network timeout and never publishes a failure.
			ctx, cancel := context.WithTimeout(ctx, hc.timeout)
			defer cancel()
			log.Debugln("Health Checking, proxy: %s, url: %s, id: {%s}", p.Name(), url, uid)
			_, _ = p.URLTest(ctx, url, expectedStatus)
			log.Debugln("Health Checked, proxy: %s, url: %s, alive: %t, delay: %d ms uid: {%s}", p.Name(), url, p.AliveForTestUrl(url), p.LastDelayForTestUrl(url), uid)
			return nil
		})
	}
	return nextWindow
}

func (hc *HealthCheck) close() {
	hc.ctxCancel()
}

func NewHealthCheck(proxies []C.Proxy, url string, timeout uint, interval uint, lazy bool, expectedStatus utils.IntRanges[uint16]) *HealthCheck {
	if url == "" {
		expectedStatus = nil
		interval = 0
	}
	if timeout == 0 {
		timeout = 5000
	}
	ctx, cancel := context.WithCancel(context.Background())

	return &HealthCheck{
		ctx:            ctx,
		ctxCancel:      cancel,
		proxies:        append([]C.Proxy(nil), proxies...),
		url:            url,
		timeout:        time.Duration(timeout) * time.Millisecond,
		extra:          map[string]*extraOption{},
		interval:       time.Duration(interval) * time.Second,
		lazy:           lazy,
		expectedStatus: expectedStatus,
		singleDo:       singledo.NewSingle[struct{}](time.Second),
		scheduledDo:    singledo.NewSingle[struct{}](time.Second),
		recoveryDo:     singledo.NewSingle[struct{}](time.Second),
	}
}
