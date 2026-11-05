package adapter

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
)

func TestProxyHealthReadsDoNotAllocateNodeStorage(t *testing.T) {
	const samples = 200
	base := outbound.NewBase(outbound.BaseOption{Name: "fixture", Type: C.Direct})
	proxies := make([]*Proxy, samples+1)
	for i := range proxies {
		proxies[i] = NewProxy(base)
	}
	i := 0
	allocations := testing.AllocsPerRun(samples, func() {
		p := proxies[i]
		i++
		if !p.AliveForTestUrl("https://unmeasured.invalid/") || p.LastDelayForTestUrl("https://unmeasured.invalid/") != 0xffff {
			t.Fatal("reading an unmeasured node changed its default health")
		}
		if p.URLTestSucceededSince("https://unmeasured.invalid/", "*", time.Second, time.Time{}) {
			t.Fatal("unmeasured node reported a reusable result")
		}
		if len(p.DelayHistory()) != 0 || len(p.DelayHistoryForTestUrl("https://unmeasured.invalid/")) != 0 {
			t.Fatal("read created a measurement")
		}
	})
	if allocations != 0 {
		t.Fatalf("reading each untouched node allocated %.0f objects", allocations)
	}
}

func TestProxyHistoryRetainsNewestTenAndIndependentSnapshots(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, dialer := newFlightTestProxy()
		close(dialer.release)
		const firstURL, secondURL = "http://probe.test/first", "http://probe.test/second"
		var all []C.DelayHistory
		byURL := map[string][]C.DelayHistory{}
		for i := range 27 {
			url := firstURL
			if i%2 != 0 {
				url = secondURL
			}
			delay, err := p.URLTest(context.Background(), url, nil)
			if err != nil {
				t.Fatal(err)
			}
			record := C.DelayHistory{Time: time.Now(), Delay: delay}
			all = append(all, record)
			byURL[url] = append(byURL[url], record)
		}
		wantGlobal := all[len(all)-10:]
		if got := p.DelayHistory(); !reflect.DeepEqual(got, wantGlobal) {
			t.Fatalf("global history order or limit changed: %+v", got)
		}
		for url, records := range byURL {
			want := records[len(records)-10:]
			if got := p.DelayHistoryForTestUrl(url); !reflect.DeepEqual(got, want) {
				t.Fatalf("%s history order or limit changed: %+v", url, got)
			}
			if got := p.ExtraDelayHistories()[url]; !got.Alive || !reflect.DeepEqual(got.History, want) {
				t.Fatalf("%s exported history disagrees with measurements", url)
			}
			p.DelayHistoryForTestUrl(url)[0].Delay = 999
			p.ExtraDelayHistories()[url].History[0].Delay = 999
			if got := p.DelayHistoryForTestUrl(url); !reflect.DeepEqual(got, want) {
				t.Fatal("caller modified internal URL history through a returned slice")
			}
		}
		p.DelayHistory()[0].Delay = 999
		if got := p.DelayHistory(); !reflect.DeepEqual(got, wantGlobal) {
			t.Fatal("caller modified internal global history through a returned slice")
		}
	})
}

func TestProxyHealthJSONAndExpectedStatusCompatibility(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, dialer := newFlightTestProxy()
		close(dialer.release)
		marshal := func() map[string]json.RawMessage {
			t.Helper()
			encoded, err := p.MarshalJSON()
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(encoded, &fields); err != nil {
				t.Fatal(err)
			}
			return fields
		}
		before := marshal()
		if string(before["history"]) != "[]" || string(before["extra"]) != "{}" || string(before["alive"]) != "true" {
			t.Fatalf("unmeasured JSON changed: %s", before)
		}
		if p.DelayHistoryForTestUrl("missing") == nil {
			t.Fatal("missing URL history must remain an empty array")
		}
		const url = "http://probe.test/"
		expected, _ := utils.NewUnsignedRanges[uint16]("200")
		if _, err := p.URLTest(context.Background(), url, expected); err != nil {
			t.Fatal(err)
		}
		after := marshal()
		var extra map[string]C.ProxyState
		if err := json.Unmarshal(after["extra"], &extra); err != nil {
			t.Fatal(err)
		}
		if string(after["alive"]) != "true" || p.DelayHistory()[0].Delay == 0 || extra[url].Alive || len(extra[url].History) != 1 || extra[url].History[0].Delay != 0 {
			t.Fatal("unexpected HTTP status changed transport health or lost the URL-specific failure")
		}
		if p.LastDelayForTestUrl(url) != 0xffff || p.URLTestSucceededSince(url, expected.String(), time.Second, time.Time{}) {
			t.Fatal("unexpected HTTP status became a usable success")
		}
	})
}

func TestProxyHealthConcurrentResultsAndSnapshots(t *testing.T) {
	p := NewProxy(outbound.NewBase(outbound.BaseOption{Name: "fixture", Type: C.Direct}))
	previousHook := UrlTestHook
	UrlTestHook = func(url, _ string, _ uint16, alive bool) {
		if p.AliveForTestUrl(url) != alive || len(p.DelayHistoryForTestUrl(url)) == 0 {
			t.Error("published result was not readable from its hook")
		}
		_ = p.ExtraDelayHistories()
	}
	defer func() { UrlTestHook = previousHook }()
	var wg sync.WaitGroup
	for worker := range 4 {
		wg.Go(func() {
			for i := range 100 {
				url := fmt.Sprintf("fixture://invalid/%d/%d", worker, i%2)
				if _, err := p.URLTest(context.Background(), url, nil); err == nil {
					t.Error("invalid test URL unexpectedly succeeded")
				}
			}
		})
		wg.Go(func() {
			for range 100 {
				if len(p.DelayHistory()) > 10 {
					t.Error("global snapshot exceeded the history limit")
				}
				for _, state := range p.ExtraDelayHistories() {
					if len(state.History) > 10 {
						t.Error("URL snapshot exceeded the history limit")
					}
				}
				if _, err := p.MarshalJSON(); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
	states := p.ExtraDelayHistories()
	if len(states) != 8 || len(p.DelayHistory()) != 10 {
		t.Fatal("concurrent results lost a URL or history")
	}
	for _, state := range states {
		if state.Alive || len(state.History) != 10 {
			t.Fatal("URL failure history was not retained")
		}
	}
}

func BenchmarkProxyHealthStorage(b *testing.B) {
	base := outbound.NewBase(outbound.BaseOption{Name: "fixture", Type: C.Direct})
	for _, mode := range []string{"unused", "inspected", "first_result"} {
		b.Run(mode, func(b *testing.B) {
			kept := make([]*Proxy, 256)
			next := 0
			b.ReportAllocs()
			for b.Loop() {
				p := NewProxy(base)
				switch mode {
				case "inspected":
					_ = p.AliveForTestUrl("https://probe.invalid/")
					_ = p.LastDelayForTestUrl("https://probe.invalid/")
				case "first_result":
					_, _ = p.urlTestOnce(context.Background(), "fixture://invalid/", nil)
				}
				kept[next%len(kept)] = p
				next++
			}
			runtime.KeepAlive(kept)
		})
	}
	for _, mode := range []string{"record_result", "read_result", "snapshots"} {
		b.Run(mode, func(b *testing.B) {
			p := NewProxy(base)
			for range 10 {
				_, _ = p.urlTestOnce(context.Background(), "fixture://invalid/", nil)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if mode == "record_result" {
					_, _ = p.urlTestOnce(context.Background(), "fixture://invalid/", nil)
				} else if mode == "read_result" {
					_ = p.AliveForTestUrl("fixture://invalid/")
					_ = p.LastDelayForTestUrl("fixture://invalid/")
				} else {
					runtime.KeepAlive(p.DelayHistory())
					runtime.KeepAlive(p.DelayHistoryForTestUrl("fixture://invalid/"))
					runtime.KeepAlive(p.ExtraDelayHistories())
				}
			}
		})
	}
}
