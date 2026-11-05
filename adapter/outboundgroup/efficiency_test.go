package outboundgroup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/adapter/provider"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/stretchr/testify/require"
)

type efficiencyProxy struct {
	C.Proxy
	name    string
	alive   atomic.Bool
	delay   atomic.Uint32
	measure func(context.Context, string, utils.IntRanges[uint16]) (uint16, error)
}

func (p *efficiencyProxy) Name() string                { return p.name }
func (p *efficiencyProxy) AliveForTestUrl(string) bool { return p.alive.Load() }
func (p *efficiencyProxy) LastDelayForTestUrl(string) uint16 {
	if !p.alive.Load() {
		return ^uint16(0)
	}
	return uint16(p.delay.Load())
}
func (p *efficiencyProxy) URLTest(ctx context.Context, url string, expected utils.IntRanges[uint16]) (uint16, error) {
	return p.measure(ctx, url, expected)
}

func newEfficiencyProxy(name string, alive bool, delay uint16) *efficiencyProxy {
	p := &efficiencyProxy{name: name}
	p.alive.Store(alive)
	p.delay.Store(uint32(delay))
	return p
}

func efficiencyGroup(t *testing.T, tolerance uint16, proxies ...C.Proxy) (*URLTest, *regexGroupProvider) {
	t.Helper()
	pd := &regexGroupProvider{version: 1, proxies: proxies}
	group, err := NewURLTest(GroupCommonOption{Name: "fixture", URL: "https://probe.invalid"}, URLTestOption{Tolerance: tolerance}, proxies[0], []P.ProxyProvider{pd})
	require.NoError(t, err)
	return group, pd
}

func TestURLTestKeepsChoiceWhenAllDown(t *testing.T) {
	first := newEfficiencyProxy("first", false, 0)
	chosen := newEfficiencyProxy("chosen", true, 30)
	last := newEfficiencyProxy("last", false, 0)
	group, pd := efficiencyGroup(t, 0, first, chosen, last)
	require.Same(t, chosen, group.fast(false))
	chosen.alive.Store(false)
	group.ResetSelection()
	require.Same(t, chosen, group.fast(false))

	replacement := newEfficiencyProxy("chosen", false, 0)
	pd.proxies, pd.version = []C.Proxy{first, replacement, last}, pd.version+1
	group.ResetSelection()
	require.Same(t, replacement, group.fast(false))

	last.alive.Store(true)
	last.delay.Store(50)
	group.ResetSelection()
	require.Same(t, last, group.fast(false))

	pd.proxies, pd.version = []C.Proxy{first}, pd.version+1
	group.ResetSelection()
	require.Same(t, first, group.fast(false))
}

func TestURLTestToleranceIncludesFirstMember(t *testing.T) {
	for _, delays := range [][2]uint16{{110, 100}, {65530, 65520}} {
		t.Run(fmt.Sprint(delays), func(t *testing.T) {
			first := newEfficiencyProxy("first", true, delays[0])
			other := newEfficiencyProxy("other", true, delays[1])
			group, _ := efficiencyGroup(t, 20, first, other)
			group.ForceSet("first")
			require.Same(t, first, group.fast(false))
			group.ForceSet("")
			require.Same(t, first, group.fast(false))
			other.delay.Store(uint32(delays[0] - 21))
			group.ResetSelection()
			require.Same(t, other, group.fast(false))
		})
	}
}

func TestGroupURLTestCancellationStopsQueuedProbes(t *testing.T) {
	const count = 1000
	started := make(chan struct{}, count)
	var calls atomic.Int32
	proxies := make([]C.Proxy, count)
	for i := range proxies {
		proxy := newEfficiencyProxy(fmt.Sprint(i), true, 1)
		proxy.measure = func(ctx context.Context, _ string, _ utils.IntRanges[uint16]) (uint16, error) {
			calls.Add(1)
			started <- struct{}{}
			<-ctx.Done()
			return 0, ctx.Err()
		}
		proxies[i] = proxy
	}
	group, _ := efficiencyGroup(t, 0, proxies...)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := group.URLTest(ctx, "", nil)
		done <- err
	}()
	for range 64 {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal("probe workers did not start")
		}
	}
	cancel()
	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("canceled group test did not finish")
	}
	require.EqualValues(t, 64, calls.Load())
}

type dialCountingAdapter struct {
	C.ProxyAdapter
	dials *atomic.Int32
}

func (a dialCountingAdapter) DialContext(context.Context, *C.Metadata) (C.Conn, error) {
	a.dials.Add(1)
	return nil, errors.New("fixture dial")
}

func TestGroupURLTestCanceledCallerStartsNoProbes(t *testing.T) {
	var dials atomic.Int32
	proxies := make([]C.Proxy, 4*groupTestConcurrency)
	for i := range proxies {
		base := outbound.NewBase(outbound.BaseOption{Name: fmt.Sprint(i), Type: C.Http})
		proxies[i] = adapter.NewProxy(dialCountingAdapter{ProxyAdapter: base, dials: &dials})
	}
	group, _ := efficiencyGroup(t, 0, proxies...)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := group.URLTest(ctx, "", nil)
	require.Error(t, err)
	require.Zero(t, dials.Load())
	_, err = group.URLTest(context.Background(), "", nil)
	require.Error(t, err)
	require.EqualValues(t, len(proxies), dials.Load())
}

func TestGroupURLTestCollectsAllResults(t *testing.T) {
	const count = 150
	expected, err := utils.NewUnsignedRanges[uint16]("200/204")
	require.NoError(t, err)
	var calls atomic.Int32
	proxies := make([]C.Proxy, count)
	for i := range proxies {
		proxy := newEfficiencyProxy(fmt.Sprint(i), true, 1)
		proxy.measure = func(_ context.Context, url string, got utils.IntRanges[uint16]) (uint16, error) {
			calls.Add(1)
			if url != "https://probe.invalid" || got.String() != expected.String() {
				return 0, fmt.Errorf("wrong probe settings")
			}
			if i%3 == 0 {
				return 0, errors.New("fixture failure")
			}
			return uint16(i), nil
		}
		proxies[i] = proxy
	}
	group, _ := efficiencyGroup(t, 0, proxies...)
	results, err := group.URLTest(context.Background(), "", expected)
	require.NoError(t, err)
	require.EqualValues(t, count, calls.Load())
	require.Len(t, results, count-count/3)
	for i := range count {
		if i%3 != 0 {
			require.Equal(t, uint16(i), results[fmt.Sprint(i)])
		}
	}
}

type failureCheckProvider struct {
	P.ProxyProvider
	background func()
	manual     atomic.Int32
}

func (p *failureCheckProvider) HealthCheck()           { p.manual.Add(1) }
func (p *failureCheckProvider) HealthCheckBackground() { p.background() }

func TestGroupFailureRecoveryCoalescesAndCoolsDown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var checks atomic.Int32
		release := make(chan struct{})
		pd := &failureCheckProvider{background: func() { checks.Add(1); <-release }}
		group := NewGroupBase(GroupBaseOption{Name: "failure fixture", Providers: []P.ProxyProvider{pd}})
		refused := errors.New("fixture connection refused")
		group.onDialFailed(C.Vmess, refused, group.healthCheck)
		synctest.Wait()
		require.EqualValues(t, 1, checks.Load())
		var wg sync.WaitGroup
		for range 20 {
			wg.Go(func() {
				for range 50 {
					group.onDialFailed(C.Vmess, refused, group.healthCheck)
					group.onDialSuccess()
				}
			})
		}
		wg.Wait()
		synctest.Wait()
		require.EqualValues(t, 1, checks.Load())
		close(release)
		synctest.Wait()
		for range 1000 {
			group.onDialFailed(C.Vmess, refused, group.healthCheck)
		}
		synctest.Wait()
		require.EqualValues(t, 1, checks.Load())
		time.Sleep(time.Second - time.Nanosecond)
		group.onDialFailed(C.Vmess, refused, group.healthCheck)
		synctest.Wait()
		require.EqualValues(t, 1, checks.Load())
		time.Sleep(time.Nanosecond)
		group.onDialFailed(C.Vmess, refused, group.healthCheck)
		synctest.Wait()
		require.EqualValues(t, 2, checks.Load())
		require.Zero(t, pd.manual.Load())
	})
}

func TestGroupFailureThresholdAndSuccessReset(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var checks atomic.Int32
		group := NewGroupBase(GroupBaseOption{Name: "failure fixture", MaxFailedTimes: 3, TestTimeout: 5000})
		check := func() { checks.Add(1) }
		fail := func() { group.onDialFailed(C.Vmess, context.DeadlineExceeded, check) }
		for _, err := range []error{nil, context.Canceled, fmt.Errorf("wrapped: %w", context.Canceled), C.ErrNotSupport} {
			group.onDialFailed(C.Vmess, err, check)
		}
		group.onDialFailed(C.Direct, errors.New("connection refused"), check)
		fail()
		fail()
		synctest.Wait()
		require.Zero(t, checks.Load())
		group.onDialSuccess()
		fail()
		fail()
		synctest.Wait()
		require.Zero(t, checks.Load())
		time.Sleep(6 * time.Second)
		fail()
		fail()
		synctest.Wait()
		require.Zero(t, checks.Load())
		fail()
		synctest.Wait()
		require.EqualValues(t, 1, checks.Load())

		single := NewGroupBase(GroupBaseOption{Name: "single failure", MaxFailedTimes: 1})
		single.onDialFailed(C.Vmess, context.DeadlineExceeded, check)
		synctest.Wait()
		require.EqualValues(t, 2, checks.Load())
	})
}

func TestGroupFailureRecoveryPausesWithBackgroundChecks(t *testing.T) {
	for _, suspended := range []bool{false, true} {
		t.Run(fmt.Sprint(suspended), func(t *testing.T) {
			provider.SetHealthCheckState(true, suspended)
			defer provider.SetHealthCheckState(false, false)
			synctest.Test(t, func(t *testing.T) {
				var checks atomic.Int32
				group := NewGroupBase(GroupBaseOption{Name: "sleeping fixture", MaxFailedTimes: 1})
				for range 1000 {
					group.onDialFailed(C.Vmess, errors.New("connection refused"), func() { checks.Add(1) })
					group.onDialFailed(C.Vmess, context.DeadlineExceeded, func() { checks.Add(1) })
				}
				synctest.Wait()
				require.Zero(t, checks.Load())
			})
			provider.SetHealthCheckState(false, false)
			synctest.Test(t, func(t *testing.T) {
				var checks atomic.Int32
				group := NewGroupBase(GroupBaseOption{Name: "awake fixture", MaxFailedTimes: 1})
				group.onDialFailed(C.Vmess, context.DeadlineExceeded, func() { checks.Add(1) })
				synctest.Wait()
				require.EqualValues(t, 1, checks.Load())
			})
		})
	}
}

func TestGroupSelectionConcurrentReadersAndWriters(t *testing.T) {
	proxies := []C.Proxy{newEfficiencyProxy("first", true, 20), newEfficiencyProxy("second", true, 10)}
	urlTest, pd := efficiencyGroup(t, 0, proxies...)
	providers := []P.ProxyProvider{pd}
	option := GroupCommonOption{Name: "fixture"}
	selector, err := NewSelector(option, SelectorOption{DefaultSelected: "second"}, proxies[0], providers)
	require.NoError(t, err)
	require.Equal(t, "second", selector.Now())
	fallback, err := NewFallback(option, FallbackOption{}, proxies[0], providers)
	require.NoError(t, err)
	for _, group := range []interface {
		ProxyGroup
		ForceSet(string)
		MarshalJSON() ([]byte, error)
	}{selector, urlTest, fallback} {
		var wg sync.WaitGroup
		wg.Go(func() {
			for i := range 200 {
				group.ForceSet(proxies[i%2].Name())
			}
		})
		for range 2 {
			wg.Go(func() {
				for range 200 {
					if resetter, ok := group.(interface{ ResetSelection() }); ok {
						resetter.ResetSelection()
					}
					_ = group.Now()
					_ = Summary(group)
					data, err := group.MarshalJSON()
					if err != nil || !json.Valid(data) {
						t.Error("invalid group JSON", err)
					}
				}
			})
		}
		wg.Wait()
		group.ForceSet("second")
		require.Equal(t, "second", group.Now())
		if fixed, ok := Summary(group)["fixed"]; ok {
			require.Equal(t, "second", fixed)
		}
	}
}

func TestFallbackDeadPinUsesAnAliveMember(t *testing.T) {
	first := newEfficiencyProxy("first", false, 0)
	alive := newEfficiencyProxy("alive", true, 10)
	pin := newEfficiencyProxy("pin", false, 0)
	for _, proxies := range [][]C.Proxy{{first, pin, alive}, {first, alive, pin}} {
		pd := &regexGroupProvider{version: 1, proxies: proxies}
		group, err := NewFallback(GroupCommonOption{Name: "fixture"}, FallbackOption{}, first, []P.ProxyProvider{pd})
		require.NoError(t, err)
		group.ForceSet("pin")
		require.Equal(t, "alive", group.Now())
		require.Equal(t, "", Summary(group)["fixed"])
	}
}

type blockedSelectionProxy struct {
	*efficiencyProxy
	entered chan struct{}
	release chan struct{}
}

func (p *blockedSelectionProxy) AliveForTestUrl(string) bool {
	select {
	case p.entered <- struct{}{}:
	default:
	}
	<-p.release
	return false
}

func TestFallbackOldDeadPinDoesNotClearNewSelection(t *testing.T) {
	first := newEfficiencyProxy("first", true, 20)
	chosen := newEfficiencyProxy("new selection", true, 10)
	blocked := &blockedSelectionProxy{
		efficiencyProxy: newEfficiencyProxy("dead pin", false, 0),
		entered:         make(chan struct{}, 1), release: make(chan struct{}),
	}
	defer close(blocked.release)
	pd := &regexGroupProvider{version: 1, proxies: []C.Proxy{first, blocked, chosen}}
	group, err := NewFallback(GroupCommonOption{Name: "fixture"}, FallbackOption{}, first, []P.ProxyProvider{pd})
	require.NoError(t, err)
	group.ForceSet(blocked.Name())
	done := make(chan string, 1)
	go func() { done <- group.Now() }()
	select {
	case <-blocked.entered:
	case <-time.After(time.Second):
		t.Fatal("selection did not inspect the pinned node")
	}
	group.ForceSet(chosen.Name())
	blocked.release <- struct{}{}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("selection did not finish")
	}
	require.Equal(t, chosen.Name(), Summary(group)["fixed"])
	require.Equal(t, chosen.Name(), group.Now())
}
