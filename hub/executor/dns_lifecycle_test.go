package executor

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/fakeip"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"

	D "github.com/miekg/dns"
)

func keepDNSGlobals(t *testing.T) *[]func() {
	t.Helper()
	oldDefault, oldProxy, oldDirect, oldSystem := resolver.DefaultResolver, resolver.ProxyServerHostResolver, resolver.DirectHostResolver, resolver.SystemResolver
	oldMapper, oldService, oldHosts := resolver.DefaultHostMapper, resolver.DefaultService, resolver.UseSystemHosts
	oldRetire := dnsRetireAfter
	t.Cleanup(func() {
		updateDNS(&config.DNS{}, false)
		dnsRetireAfter = oldRetire
		resolver.DefaultResolver, resolver.ProxyServerHostResolver, resolver.DirectHostResolver, resolver.SystemResolver = oldDefault, oldProxy, oldDirect, oldSystem
		resolver.DefaultHostMapper, resolver.DefaultService, resolver.UseSystemHosts = oldMapper, oldService, oldHosts
	})
	resolver.DefaultResolver, resolver.ProxyServerHostResolver, resolver.DirectHostResolver = nil, nil, nil
	resolver.DefaultHostMapper, resolver.DefaultService = nil, nil
	scheduled := new([]func())
	dnsRetireAfter = func(grace time.Duration, retire func()) *time.Timer {
		if grace != resolver.DefaultDNSTimeout {
			t.Errorf("retirement grace = %s, want %s", grace, resolver.DefaultDNSTimeout)
		}
		*scheduled = append(*scheduled, retire)
		return nil
	}
	return scheduled
}

func TestDNSReplacementRetiresOnlyConfiguredResolvers(t *testing.T) {
	scheduled := keepDNSGlobals(t)
	servers := []dns.NameServer{{Net: "rcode", Addr: "success"}}
	system := dns.NewResolver(dns.Config{Main: servers})
	defer system.CloseQueries()
	resolver.SystemResolver = system
	query := new(D.Msg)
	query.SetQuestion("reload.test.", D.TypeA)
	check := func(r resolver.Resolver, closed bool) {
		t.Helper()
		_, err := r.ExchangeContext(context.Background(), query.Copy())
		if closed && !errors.Is(err, context.Canceled) || !closed && err != nil {
			t.Fatalf("closed=%v, exchange error=%v", closed, err)
		}
	}
	cfg := &config.DNS{Enable: true, NameServer: servers, ProxyServerNameserver: servers, DirectNameServer: servers}
	updateDNS(cfg, true)
	previous := installedResolvers()
	for _, r := range previous {
		check(r, false)
	}
	*scheduled = nil
	updateDNS(cfg, true)
	for _, r := range previous {
		check(r, false)
	}
	if len(*scheduled) != 1 {
		t.Fatalf("replacement scheduled %d retirements", len(*scheduled))
	}
	(*scheduled)[0]()
	for _, r := range previous {
		check(r, true)
	}
	check(system, false)
	current := installedResolvers()
	for _, r := range current {
		check(r, false)
	}
	updateDNS(&config.DNS{}, false)
	for _, r := range current {
		check(r, true)
	}
	if len(*scheduled) != 1 {
		t.Fatal("disabled DNS deferred its retirement")
	}
	if resolver.DefaultResolver != nil || resolver.ProxyServerHostResolver != nil || resolver.DirectHostResolver != nil || resolver.DefaultService != nil || resolver.DefaultHostMapper != nil {
		t.Fatal("disabled DNS retained retired configuration")
	}
	updateDNS(cfg, true)
	check(resolver.DefaultResolver, false)
	check(system, false)
}

type heldDNSProxy struct {
	*outbound.Base
	started chan struct{}
	release chan struct{}
}

func (p *heldDNSProxy) DialContext(ctx context.Context, _ *C.Metadata) (C.Conn, error) {
	p.started <- struct{}{}
	select {
	case <-p.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		conn := &D.Conn{Conn: server}
		query, err := conn.ReadMsg()
		if err != nil {
			return
		}
		reply := new(D.Msg).SetReply(query)
		header := D.RR_Header{Name: query.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}
		reply.Answer = []D.RR{&D.A{Hdr: header, A: net.IPv4(192, 0, 2, 1).To4()}}
		_ = conn.WriteMsg(reply)
	}()
	return outbound.NewConn(client, p), nil
}

func TestDNSReloadLetsInFlightLookupsFinish(t *testing.T) {
	scheduled := keepDNSGlobals(t)
	proxy := &heldDNSProxy{Base: outbound.NewBase(outbound.BaseOption{Name: "held-dns"}), started: make(chan struct{}, 4), release: make(chan struct{})}
	cfg := &config.DNS{Enable: true, NameServer: []dns.NameServer{{Net: "tcp", Addr: "127.0.0.1:53", ProxyAdapter: proxy}}}
	updateDNS(cfg, true)
	previous := resolver.DefaultResolver
	type result struct {
		ips []netip.Addr
		err error
	}
	done := make(chan result, 1)
	go func() {
		ips, err := previous.LookupIPv4(context.Background(), "inflight.test")
		done <- result{ips, err}
	}()
	select {
	case <-proxy.started:
	case <-time.After(time.Second):
		t.Fatal("lookup did not reach the DNS server")
	}
	*scheduled = nil
	updateDNS(cfg, true)
	close(proxy.release)
	select {
	case got := <-done:
		if got.err != nil || len(got.ips) != 1 || got.ips[0] != netip.MustParseAddr("192.0.2.1") {
			t.Fatalf("in-flight lookup across reload: ips=%v err=%v", got.ips, got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("in-flight lookup did not finish")
	}
	for _, retire := range *scheduled {
		retire()
	}
	if _, err := previous.LookupIPv4(context.Background(), "late.test"); !errors.Is(err, context.Canceled) {
		t.Fatalf("replaced resolver after grace: %v", err)
	}
}

func TestShutdownKeepsFakeIPMappings(t *testing.T) {
	keepDNSGlobals(t)
	fakeIPConfig := func() *config.DNS {
		pool, err := fakeip.New(fakeip.Options{IPNet: netip.MustParsePrefix("198.18.0.1/16"), Size: 64})
		if err != nil {
			t.Fatal(err)
		}
		return &config.DNS{Enable: true, EnhancedMode: C.DNSFakeIP, FakeIPPool: pool, NameServer: []dns.NameServer{{Net: "rcode", Addr: "success"}}}
	}
	first := fakeIPConfig()
	updateDNS(first, true)
	retired := installedResolvers()
	ip := first.FakeIPPool.Lookup("kept.test")
	Shutdown()
	if resolver.DefaultResolver != nil || resolver.ProxyServerHostResolver != nil || resolver.DirectHostResolver != nil || resolver.DefaultService != nil {
		t.Fatal("shutdown left configured resolvers installed")
	}
	query := new(D.Msg).SetQuestion("shutdown.test.", D.TypeA)
	for _, r := range retired {
		if _, err := r.ExchangeContext(context.Background(), query.Copy()); !errors.Is(err, context.Canceled) {
			t.Fatalf("shutdown left a resolver active: %v", err)
		}
	}
	next := fakeIPConfig()
	updateDNS(next, true)
	if host, ok := resolver.FindHostByIP(ip); !ok || host != "kept.test" {
		t.Fatalf("fake IP %s after restart maps to %q, %v", ip, host, ok)
	}
	if again := next.FakeIPPool.Lookup("kept.test"); again != ip {
		t.Fatalf("restart reassigned kept.test from %s to %s", ip, again)
	}
}

func TestDNSInstallWrapsProxyServerResolverBeforeProvidersLoad(t *testing.T) {
	keepDNSGlobals(t)
	previous := WrapProxyServerResolver
	t.Cleanup(func() { WrapProxyServerResolver = previous })
	type wrapped struct{ resolver.Resolver }
	WrapProxyServerResolver = func(r resolver.Resolver) resolver.Resolver { return &wrapped{r} }
	servers := []dns.NameServer{{Net: "rcode", Addr: "success"}}
	updateDNS(&config.DNS{Enable: true, NameServer: servers, ProxyServerNameserver: servers}, true)
	if _, ok := resolver.ProxyServerHostResolver.(*wrapped); !ok {
		t.Fatalf("proxy-server resolver = %T, want the installed wrapper", resolver.ProxyServerHostResolver)
	}
}
