package outboundgroup

import (
	"strings"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

type regexGroupProvider struct {
	P.ProxyProvider
	version uint32
	proxies []C.Proxy
}

func (p *regexGroupProvider) Version() uint32            { return p.version }
func (p *regexGroupProvider) Proxies() []C.Proxy         { return p.proxies }
func (p *regexGroupProvider) VehicleType() P.VehicleType { return P.HTTP }

type regexGroupProxy struct {
	C.Proxy
	name  string
	reads int
}

func (p *regexGroupProxy) Name() string { p.reads++; return p.name }

func TestGroupFilterTimeoutPreservesSelectionUntilProviderChanges(t *testing.T) {
	good := &regexGroupProxy{name: "aaaa"}
	bad := &regexGroupProxy{name: strings.Repeat("a", 512) + "!"}
	pd := &regexGroupProvider{version: 1, proxies: []C.Proxy{good}}
	group := NewGroupBase(GroupBaseOption{Name: "test", Filter: `^(a+)+$`, Providers: []P.ProxyProvider{pd}, EmptyFallback: good})
	if got := group.GetProxies(false); len(got) != 1 || got[0] != good {
		t.Fatal("valid selection failed")
	}
	pd.version++
	pd.proxies = []C.Proxy{bad}
	if got := group.GetProxies(false); len(got) != 1 || got[0] != good {
		t.Fatal("timeout replaced the last valid selection")
	}
	reads := bad.reads
	for range 20 {
		group.GetProxies(false)
	}
	if bad.reads != reads {
		t.Fatal("every dial retried a known failing filter")
	}
	repaired := &regexGroupProxy{name: "aaa"}
	pd.version++
	pd.proxies = []C.Proxy{repaired}
	if got := group.GetProxies(false); len(got) != 1 || got[0] != repaired {
		t.Fatal("provider update did not retry the filter")
	}
}

func TestGroupFilterTimeoutExpiresWithoutProviderChange(t *testing.T) {
	fallback := &regexGroupProxy{name: "fallback"}
	pd := &regexGroupProvider{version: 1, proxies: []C.Proxy{&regexGroupProxy{name: strings.Repeat("a", 512) + "!"}}}
	group := NewGroupBase(GroupBaseOption{Name: "test", Filter: `^(a+)+$`, Providers: []P.ProxyProvider{pd}, EmptyFallback: fallback})
	if got := group.GetProxies(false); len(got) != 1 || got[0] != fallback {
		t.Fatal("failed first evaluation did not use the fallback")
	}
	recovered := &regexGroupProxy{name: "aaa"}
	pd.proxies = []C.Proxy{recovered}
	if got := group.GetProxies(false); len(got) != 1 || got[0] != fallback {
		t.Fatal("known failing filter was retried before its backoff")
	}
	group.filterRetryAt = time.Now().Add(-time.Nanosecond)
	if got := group.GetProxies(false); len(got) != 1 || got[0] != recovered {
		t.Fatal("filter failure outlived its backoff on an unchanged provider")
	}
	reads := recovered.reads
	group.GetProxies(false)
	if recovered.reads != reads {
		t.Fatal("successful retry was not cached")
	}
}
