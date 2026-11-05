package outboundgroup

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/adapter/provider"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"

	"github.com/dlclark/regexp2"
	"golang.org/x/exp/slices"
)

type GroupBase struct {
	*outbound.Base
	hidden            bool
	icon              string
	filterRegs        []*regexp2.Regexp
	excludeFilterRegs []*regexp2.Regexp
	excludeTypeArray  []string
	providers         []P.ProxyProvider
	failedTestMux     sync.Mutex
	failedTimes       int
	failedTime        time.Time
	failedTesting     bool
	failedCheckAfter  time.Time
	testTimeout       int
	maxFailedTimes    int
	emptyFallback     C.Proxy

	// for GetProxies
	getProxiesMutex  sync.Mutex
	providerVersions []uint32
	providerProxies  []C.Proxy
	filterRetryAt    time.Time
}

type GroupBaseOption struct {
	Name           string
	Type           C.AdapterType
	Hidden         bool
	Icon           string
	Filter         string
	ExcludeFilter  string
	ExcludeType    string
	TestTimeout    int
	MaxFailedTimes int
	EmptyFallback  C.Proxy
	Providers      []P.ProxyProvider
}

func NewGroupBase(opt GroupBaseOption) *GroupBase {
	var excludeTypeArray []string
	if opt.ExcludeType != "" {
		excludeTypeArray = strings.Split(opt.ExcludeType, "|")
	}

	var excludeFilterRegs []*regexp2.Regexp
	if opt.ExcludeFilter != "" {
		for _, excludeFilter := range strings.Split(opt.ExcludeFilter, "`") {
			excludeFilterReg := utils.MustCompileNameRegex(excludeFilter)
			excludeFilterRegs = append(excludeFilterRegs, excludeFilterReg)
		}
	}

	var filterRegs []*regexp2.Regexp
	if opt.Filter != "" {
		for _, filter := range strings.Split(opt.Filter, "`") {
			filterReg := utils.MustCompileNameRegex(filter)
			filterRegs = append(filterRegs, filterReg)
		}
	}

	gb := &GroupBase{
		Base:              outbound.NewBase(outbound.BaseOption{Name: opt.Name, Type: opt.Type}),
		hidden:            opt.Hidden,
		icon:              opt.Icon,
		filterRegs:        filterRegs,
		excludeFilterRegs: excludeFilterRegs,
		excludeTypeArray:  excludeTypeArray,
		providers:         opt.Providers,
		testTimeout:       opt.TestTimeout,
		maxFailedTimes:    opt.MaxFailedTimes,
		emptyFallback:     opt.EmptyFallback,
	}

	if gb.testTimeout == 0 {
		gb.testTimeout = 5000
	}
	if gb.maxFailedTimes == 0 {
		gb.maxFailedTimes = 5
	}

	return gb
}

func (gb *GroupBase) Hidden() bool {
	return gb.hidden
}

func (gb *GroupBase) Icon() string {
	return gb.icon
}

func (gb *GroupBase) EmptyFallback() C.Proxy {
	return gb.emptyFallback
}

func (gb *GroupBase) Touch() {
	for _, pd := range gb.providers {
		pd.Touch()
	}
}

func (gb *GroupBase) GetProxies(touch bool) []C.Proxy {
	providerVersions := make([]uint32, len(gb.providers))
	for i, pd := range gb.providers {
		if touch { // touch first
			pd.Touch()
		}
		providerVersions[i] = pd.Version()
	}

	// thread safe
	gb.getProxiesMutex.Lock()
	defer gb.getProxiesMutex.Unlock()

	// return the cached proxies if version not changed
	if slices.Equal(providerVersions, gb.providerVersions) && (gb.filterRetryAt.IsZero() || time.Now().Before(gb.filterRetryAt)) {
		return gb.providerProxies
	}
	var filterError error
	matchName := func(pattern *regexp2.Regexp, name string) bool {
		if filterError != nil {
			return false
		}
		matched, err := pattern.MatchString(name)
		filterError = err
		return matched
	}

	var proxies []C.Proxy
	if len(gb.filterRegs) == 0 {
		for _, pd := range gb.providers {
			proxies = append(proxies, pd.Proxies()...)
		}
	} else {
		for _, pd := range gb.providers {
			if pd.VehicleType() == P.Compatible { // compatible provider unneeded filter
				proxies = append(proxies, pd.Proxies()...)
				continue
			}

			var newProxies []C.Proxy
			proxiesSet := map[string]struct{}{}
			for _, filterReg := range gb.filterRegs {
				for _, p := range pd.Proxies() {
					name := p.Name()
					if matchName(filterReg, name) {
						if _, ok := proxiesSet[name]; !ok {
							proxiesSet[name] = struct{}{}
							newProxies = append(newProxies, p)
						}
					}
				}
			}
			proxies = append(proxies, newProxies...)
		}
	}

	// Multiple filers means that proxies are sorted in the order in which the filers appear.
	// Although the filter has been performed once in the previous process,
	// when there are multiple providers, the array needs to be reordered as a whole.
	if len(gb.providers) > 1 && len(gb.filterRegs) > 1 {
		var newProxies []C.Proxy
		proxiesSet := map[string]struct{}{}
		for _, filterReg := range gb.filterRegs {
			for _, p := range proxies {
				name := p.Name()
				if matchName(filterReg, name) {
					if _, ok := proxiesSet[name]; !ok {
						proxiesSet[name] = struct{}{}
						newProxies = append(newProxies, p)
					}
				}
			}
		}
		for _, p := range proxies { // add not matched proxies at the end
			name := p.Name()
			if _, ok := proxiesSet[name]; !ok {
				proxiesSet[name] = struct{}{}
				newProxies = append(newProxies, p)
			}
		}
		proxies = newProxies
	}

	if len(gb.excludeFilterRegs) > 0 {
		var newProxies []C.Proxy
	LOOP1:
		for _, p := range proxies {
			name := p.Name()
			for _, excludeFilterReg := range gb.excludeFilterRegs {
				if matchName(excludeFilterReg, name) {
					continue LOOP1
				}
			}
			newProxies = append(newProxies, p)
		}
		proxies = newProxies
	}

	if gb.excludeTypeArray != nil {
		var newProxies []C.Proxy
	LOOP2:
		for _, p := range proxies {
			mType := p.Type().String()
			for _, excludeType := range gb.excludeTypeArray {
				if strings.EqualFold(mType, excludeType) {
					continue LOOP2
				}
			}
			newProxies = append(newProxies, p)
		}
		proxies = newProxies
	}

	if filterError != nil {
		log.Errorln("Proxy group %s filter evaluation failed; keeping the last selection: %v", gb.Name(), filterError)
		gb.providerVersions = providerVersions
		gb.filterRetryAt = time.Now().Add(filterRetryInterval)
		if len(gb.providerProxies) == 0 {
			gb.providerProxies = []C.Proxy{gb.EmptyFallback()}
		}
		return gb.providerProxies
	}
	if len(proxies) == 0 {
		return []C.Proxy{gb.EmptyFallback()}
	}

	// only cache when proxies not empty
	gb.providerVersions = providerVersions
	gb.providerProxies = proxies
	gb.filterRetryAt = time.Time{}

	return proxies
}

func (gb *GroupBase) URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (map[string]uint16, error) {
	var wg sync.WaitGroup
	var lock sync.Mutex
	mp := map[string]uint16{}
	proxies := gb.GetProxies(false)
	running := make(chan struct{}, groupTestConcurrency)
schedule:
	for _, proxy := range proxies {
		select {
		case <-ctx.Done():
			break schedule
		case running <- struct{}{}:
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-running }()
			delay, err := proxy.URLTest(ctx, url, expectedStatus)
			if err == nil {
				lock.Lock()
				mp[proxy.Name()] = delay
				lock.Unlock()
			}
		}()
	}
	wg.Wait()

	if len(mp) == 0 {
		return mp, fmt.Errorf("get delay: all proxies timeout")
	} else {
		return mp, nil
	}
}

func (gb *GroupBase) onDialFailed(adapterType C.AdapterType, err error, fn func()) {
	if adapterType == C.Direct || adapterType == C.Compatible || adapterType == C.Reject || adapterType == C.Pass || adapterType == C.RejectDrop {
		return
	}

	if err == nil || errors.Is(err, C.ErrNotSupport) || errors.Is(err, context.Canceled) || provider.BackgroundHealthChecksPaused() {
		return
	}

	gb.failedTestMux.Lock()
	defer gb.failedTestMux.Unlock()
	now := time.Now()
	if gb.failedTesting || now.Before(gb.failedCheckAfter) {
		return
	}
	if !strings.Contains(err.Error(), "connection refused") {
		if gb.failedTimes == 0 || now.Sub(gb.failedTime) > time.Duration(gb.testTimeout)*time.Millisecond {
			gb.failedTimes = 0
			gb.failedTime = now
		}
		gb.failedTimes++
		if gb.failedTimes < gb.maxFailedTimes {
			return
		}
		log.Warnln("because %s failed multiple times, activate health check", gb.Name())
	}
	gb.failedTimes = 0
	gb.failedTesting = true
	go func() {
		defer func() {
			gb.failedTestMux.Lock()
			gb.failedTesting = false
			gb.failedCheckAfter = time.Now().Add(failedCheckCooldown)
			gb.failedTestMux.Unlock()
		}()
		if !provider.BackgroundHealthChecksPaused() {
			fn()
		}
	}()
}

func (gb *GroupBase) healthCheck() {
	// onDialFailed admits one recovery round before starting its worker.
	wg := sync.WaitGroup{}
	for _, proxyProvider := range gb.providers {
		wg.Add(1)
		proxyProvider := proxyProvider
		go func() {
			defer wg.Done()
			if background, ok := proxyProvider.(interface{ HealthCheckBackground() }); ok {
				background.HealthCheckBackground()
			} else {
				proxyProvider.HealthCheck()
			}
		}()
	}

	wg.Wait()
}

func (gb *GroupBase) onDialSuccess() {
	gb.failedTestMux.Lock()
	defer gb.failedTestMux.Unlock()
	if !gb.failedTesting {
		gb.failedTimes = 0
	}
}

const (
	groupTestConcurrency = 64
	failedCheckCooldown  = time.Second
	filterRetryInterval  = 30 * time.Second
)
