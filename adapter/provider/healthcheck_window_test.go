package provider

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/metacubex/mihomo/common/singledo"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
)

type windowMeasurements struct {
	sync.Mutex
	byURL map[string]map[string]int
}

func (m *windowMeasurements) record(name, url, _ string) {
	m.Lock()
	defer m.Unlock()
	if m.byURL == nil {
		m.byURL = make(map[string]map[string]int)
	}
	if m.byURL[url] == nil {
		m.byURL[url] = make(map[string]int)
	}
	m.byURL[url][name]++
}

func windowTestProxies(count int, measure func(string, string, string)) []C.Proxy {
	proxies := make([]C.Proxy, count)
	for i := range proxies {
		proxies[i] = &fakeHealthProxy{name: fmt.Sprintf("node-%04d", i), delay: 0xffff, measure: measure}
	}
	return proxies
}

func TestScheduledHealthCheckRotatesLargeProviders(t *testing.T) {
	for _, manyFailed := range []bool{false, true} {
		t.Run(fmt.Sprint(manyFailed), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				isolateHealthSchedule(t)
				const url = "https://probe.invalid/"
				var measured windowMeasurements
				proxies := windowTestProxies(3000, measured.record)
				for _, proxy := range proxies {
					proxy.(*fakeHealthProxy).delay = 1000
				}
				for i := 2700; i < 2764; i++ {
					proxies[i].(*fakeHealthProxy).delay = uint16(i - 2699)
				}
				proxies[2998].(*fakeHealthProxy).failed = true
				if manyFailed {
					for i := range 2000 {
						proxies[i].(*fakeHealthProxy).failed = true
					}
				}
				SetHealthCheckPriority(func() map[string]struct{} {
					return map[string]struct{}{"node-2999": {}}
				})
				hc := NewHealthCheck(proxies, " "+url+" ", 1000, 0, false, nil)
				defer hc.close()
				seen := make(map[string]bool)
				for round := range 6 {
					hc.checkScheduled()
					got := measured.byURL[url]
					if len(got) != 1000 {
						t.Fatalf("round %d measured %d nodes, want 1000", round, len(got))
					}
					if got["node-2999"] != 1 || (!manyFailed && got["node-2998"] != 1) {
						t.Fatal("selected or failed node lost its priority")
					}
					for i := 2700; i < 2764; i++ {
						if got[proxies[i].Name()] != 1 {
							t.Fatalf("known fast node %d was not rechecked", i)
						}
					}
					for name, count := range got {
						if count != 1 {
							t.Fatalf("%s was measured %d times in one round", name, count)
						}
						seen[name] = true
					}
					measured.byURL = nil
					time.Sleep(time.Second)
				}
				if len(seen) != len(proxies) {
					t.Fatalf("rotation reached %d of %d nodes", len(seen), len(proxies))
				}
			})
		})
	}
}

func TestHealthCheckWindowsRespectFiltersAndIndependentURLs(t *testing.T) {
	isolateHealthSchedule(t)
	var measured windowMeasurements
	proxies := windowTestProxies(5000, measured.record)
	hc := NewHealthCheck(proxies, "", 1000, 0, false, nil)
	defer hc.close()
	hc.scheduledDo = singledo.NewSingle[struct{}](0)
	expectedA, _ := utils.NewUnsignedRanges[uint16]("204")
	expectedB, _ := utils.NewUnsignedRanges[uint16]("200-299")
	hc.registerHealthCheckTask("https://a.invalid/", expectedA, "[02468]$", 0)
	hc.registerHealthCheckTask("https://b.invalid/", expectedB, "[13579]$", 0)
	hc.registerHealthCheckTask("https://small.invalid/", nil, "^node-499[89]$", 0)
	SetHealthCheckPriority(func() map[string]struct{} {
		return map[string]struct{}{"node-4999": {}}
	})
	for i, proxy := range proxies {
		p := proxy.(*fakeHealthProxy)
		p.delay = uint16(i + 1)
		p.measure = func(name, url, expected string) {
			last := name[len(name)-1]
			switch url {
			case "https://a.invalid/":
				if last%2 != 0 || expected != expectedA.String() {
					t.Errorf("wrong even-node probe: %s %s", name, expected)
				}
			case "https://b.invalid/":
				if last%2 != 1 || expected != expectedB.String() {
					t.Errorf("wrong odd-node probe: %s %s", name, expected)
				}
			}
			measured.record(name, url, expected)
		}
	}
	seen := map[string]map[string]bool{}
	for round := range 3 {
		hc.checkScheduled()
		for url, names := range measured.byURL {
			want := 1000
			if url == "https://small.invalid/" {
				want = 2
			}
			if len(names) != want {
				t.Fatalf("round %d: %s measured %d, want %d", round, url, len(names), want)
			}
			if seen[url] == nil {
				seen[url] = make(map[string]bool)
			}
			for name, count := range names {
				if count != 1 {
					t.Fatalf("duplicate probe: %s %s", url, name)
				}
				seen[url][name] = true
			}
		}
		if measured.byURL["https://b.invalid/"]["node-4999"] != 1 {
			t.Fatal("selected matching node missing")
		}
		if measured.byURL["https://a.invalid/"]["node-0126"] != 1 || measured.byURL["https://b.invalid/"]["node-0127"] != 1 {
			t.Fatal("fast candidates were selected before applying each URL's filter")
		}
		measured.byURL = nil
	}
	if len(seen["https://a.invalid/"]) != 2500 || len(seen["https://b.invalid/"]) != 2500 || len(seen["https://small.invalid/"]) != 2 {
		t.Fatal("filtered URL rotations did not cover all matching nodes")
	}
}

func TestManualAndRecoveryHealthChecksCoverTheWholeProvider(t *testing.T) {
	isolateHealthSchedule(t)
	const url = "https://probe.invalid/"
	var measured windowMeasurements
	proxies := windowTestProxies(3000, measured.record)
	hc := NewHealthCheck(proxies, url, 1000, 0, false, nil)
	defer hc.close()
	hc.checkScheduled()
	measured.byURL = nil
	bp := &baseProvider{healthCheck: hc}
	bp.HealthCheckBackground()
	if len(measured.byURL[url]) != len(proxies) {
		t.Fatal("recovery reused a partial scheduled round")
	}
	measured.byURL = nil
	SetHealthCheckState(true, false)
	bp.HealthCheck()
	if len(measured.byURL[url]) != len(proxies) {
		t.Fatal("manual check was limited or blocked by idle")
	}
}

func TestHealthCheckOwnsPublishedProxySlices(t *testing.T) {
	isolateHealthSchedule(t)
	const url = "https://probe.invalid/"
	var original, replacement windowMeasurements
	proxies := windowTestProxies(17, original.record)
	hc := NewHealthCheck(proxies, url, 1000, 0, false, nil)
	defer hc.close()
	next := windowTestProxies(17, replacement.record)
	copy(proxies, next)
	hc.checkScheduled()
	if len(original.byURL[url]) != 17 || len(replacement.byURL[url]) != 0 {
		t.Fatal("constructor retained the caller's mutable slice")
	}
	hc.setProxies(next)
	clear(next)
	hc.scheduledDo.Reset()
	hc.checkScheduled()
	if len(replacement.byURL[url]) != 17 {
		t.Fatal("replacement retained the caller's mutable slice")
	}
}

func TestHealthCheckDoesNotCacheAnEmptyProviderRound(t *testing.T) {
	isolateHealthSchedule(t)
	const url = "https://probe.invalid/"
	var measured windowMeasurements
	hc := NewHealthCheck(nil, url, 1000, 0, false, nil)
	defer hc.close()
	hc.checkScheduled()
	hc.setProxies(windowTestProxies(17, measured.record))
	hc.checkScheduled()
	if len(measured.byURL[url]) != 17 {
		t.Fatal("empty startup round suppressed the first populated check")
	}
}

func TestCanceledHealthCheckWindowRetriesUnfinishedNodes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		isolateHealthSchedule(t)
		const url = "https://probe.invalid/"
		var measured windowMeasurements
		var blocking atomic.Bool
		blocking.Store(true)
		proxies := make([]C.Proxy, 1500)
		for i := range proxies {
			name := fmt.Sprintf("node-%04d", i)
			proxies[i] = &fakeHealthProxy{name: name, probe: func(ctx context.Context) {
				measured.record(name, url, "")
				if blocking.Load() {
					<-ctx.Done()
				}
			}}
		}
		hc := NewHealthCheck(proxies, url, 5000, 0, false, nil)
		defer hc.close()
		hc.scheduledDo = singledo.NewSingle[struct{}](0)
		done := make(chan struct{})
		go func() { hc.checkScheduled(); close(done) }()
		synctest.Wait()
		SetHealthCheckState(true, false)
		<-done
		if len(measured.byURL[url]) != backgroundHealthCheckLimit {
			t.Fatal("canceling a window started queued probes")
		}
		blocking.Store(false)
		measured.byURL = nil
		SetHealthCheckState(false, false)
		hc.checkScheduled()
		got := measured.byURL[url]
		if len(got) != 1000 || got["node-0999"] != 1 || got["node-1000"] != 0 {
			t.Fatal("canceled window skipped nodes that never ran")
		}
	})
}

func TestHealthCheckWindowKeepsSnapshotDuringProviderReplacement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		isolateHealthSchedule(t)
		const url = "https://probe.invalid/"
		var original, replacement windowMeasurements
		release := make(chan struct{})
		proxies := make([]C.Proxy, 2500)
		for i := range proxies {
			name := fmt.Sprintf("node-%04d", i)
			proxies[i] = &fakeHealthProxy{name: name, probe: func(context.Context) {
				original.record(name, url, "")
				<-release
			}}
		}
		hc := NewHealthCheck(proxies, url, 5000, 0, false, nil)
		defer hc.close()
		hc.scheduledDo = singledo.NewSingle[struct{}](0)
		done := make(chan struct{})
		go func() { hc.checkScheduled(); close(done) }()
		synctest.Wait()
		next := windowTestProxies(20, replacement.record)
		hc.setProxies(next)
		clear(next)
		hc.registerHealthCheckTask("https://extra.invalid/", nil, "", 0)
		close(release)
		<-done
		if len(original.byURL[url]) != 1000 || len(replacement.byURL) != 0 {
			t.Fatal("running round mixed provider generations")
		}
		hc.checkScheduled()
		if len(replacement.byURL[url]) != 20 || len(replacement.byURL["https://extra.invalid/"]) != 20 {
			t.Fatal("next round lost the replaced nodes or registered URL")
		}
	})
}

func TestHealthCheckWindowStopsOnFilterTimeout(t *testing.T) {
	isolateHealthSchedule(t)
	var measured windowMeasurements
	proxies := windowTestProxies(1001, measured.record)
	proxies[0].(*fakeHealthProxy).name = "a"
	proxies[1].(*fakeHealthProxy).name = strings.Repeat("a", 512) + "!"
	hc := NewHealthCheck(proxies, "", 1000, 0, false, nil)
	defer hc.close()
	hc.registerHealthCheckTask("https://probe.invalid/", nil, "^(a+)+$", 0)
	hc.checkScheduled()
	if len(measured.byURL) != 0 {
		t.Fatal("filter timeout published a partial health-check window")
	}
}

func BenchmarkHealthCheckScheduling(b *testing.B) {
	for _, reused := range []bool{false, true} {
		b.Run(fmt.Sprintf("reused=%t", reused), func(b *testing.B) {
			proxies := windowTestProxies(10000, func(string, string, string) {})
			hc := NewHealthCheck(proxies, "https://probe.invalid/", 1000, 0, false, nil)
			defer hc.close()
			wait := time.Duration(0)
			if reused {
				wait = time.Hour
			}
			hc.scheduledDo = singledo.NewSingle[struct{}](wait)
			hc.checkScheduled()
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				hc.checkScheduled()
			}
		})
	}
}
