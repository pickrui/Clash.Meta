package provider

import (
	"context"
	"fmt"
	"runtime"
	"sync"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

type DialerProvider struct{ *dialerProvider }

type dialerProvider struct {
	P.ProxyProvider
	dialer  string
	hc      *HealthCheck
	mu      sync.Mutex
	version uint32
	proxies []C.Proxy
	cache   map[C.Proxy]C.Proxy
	once    sync.Once
}

func NewDialerProvider(source P.ProxyProvider, dialer, url, filter string, timeout, interval uint, lazy bool, expected utils.IntRanges[uint16]) (*DialerProvider, error) {
	hc := NewHealthCheck(nil, "", timeout, interval, lazy, expected)
	hc.registerHealthCheckTask(url, expected, filter, interval)
	inner := &dialerProvider{ProxyProvider: source, dialer: dialer, hc: hc, cache: make(map[C.Proxy]C.Proxy)}
	inner.version = source.Version()
	for _, member := range source.Proxies() {
		derived, err := cloneDialerMember(member, dialer)
		if err != nil {
			hc.close()
			for original, proxy := range inner.cache {
				if proxy != original {
					_ = proxy.Close()
				}
			}
			return nil, err
		}
		inner.cache[member] = derived
		inner.proxies = append(inner.proxies, derived)
	}
	hc.proxySource = inner.Proxies
	result := &DialerProvider{inner}
	runtime.SetFinalizer(result, (*DialerProvider).Close)
	return result, nil
}

func cloneDialerMember(proxy C.Proxy, dialer string) (C.Proxy, error) {
	switch proxy.Type() {
	case C.Direct, C.Reject, C.RejectDrop, C.Relay, C.Selector, C.Fallback, C.URLTest, C.LoadBalance:
		return proxy, nil
	}
	if clone, ok := proxy.(interface{ WithDialerProxy(string) (C.Proxy, error) }); ok {
		return clone.WithDialerProxy(dialer)
	}
	return nil, fmt.Errorf("proxy [%s] cannot be a landing group member", proxy.Name())
}

func (p *dialerProvider) Proxies() []C.Proxy {
	p.mu.Lock()
	defer p.mu.Unlock()
	version := p.ProxyProvider.Version()
	if p.version == version {
		return p.proxies
	}
	next := make(map[C.Proxy]C.Proxy)
	var members []C.Proxy
	for _, original := range p.ProxyProvider.Proxies() {
		derived := p.cache[original]
		if derived == nil {
			var err error
			derived, err = cloneDialerMember(original, p.dialer)
			if err != nil {
				derived = adapter.NewProxy(&failedDialerMember{Base: outbound.NewBase(outbound.BaseOption{Name: original.Name(), Type: original.Type()}), err: err})
			}
		}
		next[original] = derived
		members = append(members, derived)
	}
	// Active connections retain their auto-closing adapter after it leaves this cache.
	p.cache, p.proxies, p.version = next, members, version
	return members
}

func (p *dialerProvider) Initial() error {
	p.once.Do(func() {
		if p.hc.auto() {
			go p.hc.process()
		}
	})
	return nil
}
func (p *dialerProvider) Touch()                 { p.hc.touch() }
func (p *dialerProvider) HealthCheck()           { p.hc.check() }
func (p *dialerProvider) HealthCheckBackground() { p.hc.checkBackground(healthCheckRecovery) }
func (p *dialerProvider) HealthCheckURL() string { return p.hc.url }
func (p *dialerProvider) RegisterHealthCheckTask(url string, expected utils.IntRanges[uint16], filter string, interval uint) {
	p.hc.registerHealthCheckTask(url, expected, filter, interval)
}
func (p *DialerProvider) Close() error {
	runtime.SetFinalizer(p, nil)
	p.hc.close()
	return nil
}

type failedDialerMember struct {
	*outbound.Base
	err error
}

func (p *failedDialerMember) DialContext(context.Context, *C.Metadata) (C.Conn, error) {
	return nil, p.err
}
func (p *failedDialerMember) ListenPacketContext(context.Context, *C.Metadata) (C.PacketConn, error) {
	return nil, p.err
}
