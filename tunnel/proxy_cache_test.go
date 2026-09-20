package tunnel

import (
	"sync"
	"sync/atomic"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

type cacheTestProxy struct {
	C.Proxy
	name string
}

func (p *cacheTestProxy) Name() string { return p.name }

type cacheTestProvider struct {
	P.ProxyProvider
	version atomic.Uint32
	mu      sync.RWMutex
	proxies []C.Proxy
}

func (p *cacheTestProvider) Version() uint32    { return p.version.Load() }
func (p *cacheTestProvider) Proxies() []C.Proxy { p.mu.RLock(); defer p.mu.RUnlock(); return p.proxies }
func (p *cacheTestProvider) replace(proxy C.Proxy) {
	p.mu.Lock()
	p.proxies = []C.Proxy{proxy}
	p.version.Add(1)
	p.mu.Unlock()
}

func TestAllProxiesCacheRefreshPreservesPublishedSnapshot(t *testing.T) {
	oldProxies, oldProviders := Proxies(), ProvidersSnapshot()
	defer UpdateProxies(oldProxies, oldProviders)
	first, second := &cacheTestProxy{name: "first"}, &cacheTestProxy{name: "second"}
	provider := &cacheTestProvider{}
	provider.replace(first)
	UpdateProxies(map[string]C.Proxy{}, map[string]P.ProxyProvider{"provider": provider})
	before := AllProxies()
	if before["first"] != first {
		t.Fatal("provider proxy missing")
	}
	provider.replace(second)
	after := AllProxies()
	if after["second"] != second || after["first"] != nil {
		t.Fatal("provider refresh retained stale proxies")
	}
	if before["first"] != first || before["second"] != nil {
		t.Fatal("published snapshot mutated")
	}
	InvalidateAllProxies()
	if AllProxies()["second"] != second {
		t.Fatal("explicit cache eviction changed routing")
	}
	UpdateProxies(map[string]C.Proxy{"direct": first}, map[string]P.ProxyProvider{})
	final := AllProxies()
	if final["direct"] != first || final["second"] != nil {
		t.Fatal("config replacement retained provider proxies")
	}
}

func TestAllProxiesCacheConcurrentProviderRefresh(t *testing.T) {
	oldProxies, oldProviders := Proxies(), ProvidersSnapshot()
	defer UpdateProxies(oldProxies, oldProviders)
	provider := &cacheTestProvider{}
	provider.replace(&cacheTestProxy{name: "node"})
	UpdateProxies(map[string]C.Proxy{}, map[string]P.ProxyProvider{"provider": provider})
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 100 {
				if AllProxies()["node"] == nil {
					t.Error("routing snapshot lost provider")
				}
			}
		})
	}
	for range 100 {
		provider.replace(&cacheTestProxy{name: "node"})
		InvalidateAllProxies()
	}
	wg.Wait()
}

func TestProxiesSnapshotDuringConfigReplacement(t *testing.T) {
	oldProxies, oldProviders := ProxiesSnapshot(), ProvidersSnapshot()
	defer UpdateProxies(oldProxies, oldProviders)
	first := &cacheTestProxy{name: "node"}
	UpdateProxies(map[string]C.Proxy{"node": first}, nil)
	before := ProxiesSnapshot()
	var readers sync.WaitGroup
	for range 4 {
		readers.Go(func() {
			for range 1000 {
				if ProxiesSnapshot()["node"] == nil {
					t.Error("snapshot lost configured proxy")
				}
			}
		})
	}
	for range 1000 {
		UpdateProxies(map[string]C.Proxy{"node": &cacheTestProxy{name: "node"}}, nil)
	}
	readers.Wait()
	if before["node"] != first {
		t.Fatal("config replacement mutated a published snapshot")
	}
}
