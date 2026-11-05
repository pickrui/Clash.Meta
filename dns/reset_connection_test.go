package dns

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/trie"
	"github.com/metacubex/mihomo/internal/testutil"

	D "github.com/miekg/dns"
)

type resetCountingClient struct {
	answeringClient
	resets atomic.Int64
	calls  atomic.Int64
}

func (c *resetCountingClient) ResetConnection() { c.resets.Add(1) }

func (c *resetCountingClient) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	c.calls.Add(1)
	return c.answeringClient.ExchangeContext(ctx, m)
}

func TestResetConnectionCoversPoliciesAndSharedTransports(t *testing.T) {
	(*Resolver)(nil).ResetConnection()
	(Resolvers{}).ResetConnection()
	shared, bootstrap, policyOnly := &resetCountingClient{}, &resetCountingClient{}, &resetCountingClient{}
	matcherOnly := &resetCountingClient{}
	proxyOnly, directOnly := &resetCountingClient{}, &resetCountingClient{}
	wrapped := clientWithDisableTypes{
		dnsClient:    clientWithEdns0Subnet{dnsClient: shared},
		disableTypes: map[uint16]struct{}{D.TypeAAAA: {}},
	}
	policies := trie.New[[]dnsClient]()
	for _, domain := range []string{"exact.test", "+.suffix.test", "*.wild.test"} {
		if err := policies.Insert(domain, []dnsClient{wrapped, policyOnly}); err != nil {
			t.Fatal(err)
		}
	}
	policies.Optimize()
	r := &Resolver{
		main:     []dnsClient{wrapped, shared},
		fallback: []dnsClient{shared},
		policy: []dnsPolicy{
			domainTriePolicy{policies},
			domainMatcherPolicy{dnsClients: []dnsClient{matcherOnly, shared}},
		},
		defaultResolver: &Resolver{main: []dnsClient{bootstrap, shared}},
	}
	rs := Resolvers{
		Resolver:       r,
		ProxyResolver:  &Resolver{main: []dnsClient{shared, proxyOnly}, policy: r.policy},
		DirectResolver: &Resolver{main: []dnsClient{wrapped, directOnly}, policy: r.policy},
	}
	for generation := int64(1); generation <= 2; generation++ {
		rs.ResetConnection()
		for name, client := range map[string]*resetCountingClient{
			"shared": shared, "bootstrap": bootstrap, "trie-policy": policyOnly, "matcher-policy": matcherOnly,
			"proxy-only": proxyOnly, "direct-only": directOnly,
		} {
			if got := client.resets.Load(); got != generation {
				t.Errorf("%s: %d resets after %d network changes", name, got, generation)
			}
		}
	}
}

func TestResetConnectionReopensConfiguredPolicyTransports(t *testing.T) {
	cert := testutil.NewCertificate(t, "front.test")
	if err := ca.AddCertificate(cert.RootPEM); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ca.ResetCertificate)
	previousHosts := resolver.DefaultHosts
	resolver.DefaultHosts = resolver.NewHosts(trie.New[resolver.HostValue]())
	t.Cleanup(func() { resolver.DefaultHosts = previousHosts })
	if err := resolver.DefaultHosts.Insert("front.test", resolver.HostValue{IPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}); err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []string{"tls", "https", "quic"} {
		for _, kind := range []string{"trie", "matcher"} {
			t.Run(protocol+"/"+kind, func(t *testing.T) {
				address, handshakes := nameDNSServer(t, protocol, cert.TLS)
				policy := Policy{
					Domain: "+.fallback-test.invalid",
					NameServers: []NameServer{{
						Net: protocol, Addr: address,
						Params: map[string]string{"disable-ipv6": "true", "ecs": "192.0.2.0/24"},
					}},
				}
				if kind == "matcher" {
					policy.Matcher = fallbackDomainMatcher{}
				}
				r := NewResolver(Config{
					Main:   []NameServer{{Net: "rcode", Addr: "success"}},
					Policy: []Policy{policy},
				})
				query := dnsQuestion("fallback-test.invalid")
				transport := rawTransport(r.matchPolicy(query)[0]).(io.Closer)
				t.Cleanup(func() { r.CloseQueries(); _ = transport.Close() })
				for generation := range 2 {
					if generation > 0 {
						r.ResetConnection()
					}
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					if _, err := r.ExchangeContext(ctx, query); err != nil {
						t.Fatal(err)
					}
					select {
					case <-handshakes:
					case <-ctx.Done():
						t.Fatalf("generation %d reused the previous network connection", generation)
					}
				}
			})
		}
	}
}

type nonComparableResetClient struct {
	dnsClient
	state  any
	resets *atomic.Int64
}

func (c nonComparableResetClient) ResetConnection() { c.resets.Add(1) }

func TestResetConnectionAcceptsNonComparableClients(t *testing.T) {
	var resets atomic.Int64
	r := &Resolver{main: []dnsClient{nonComparableResetClient{state: []byte{1}, resets: &resets}}}
	r.ResetConnection()
	if got := resets.Load(); got != 1 {
		t.Fatalf("non-comparable client: %d resets", got)
	}
}

func TestResetConnectionKeepsQueryAndCacheReusable(t *testing.T) {
	c := &resetCountingClient{answeringClient: answeringClient{address: "fixture", ip: "192.0.2.1"}}
	r := NewResolverFromClient(c)
	defer r.CloseQueries()
	query := dnsQuestion("reset.test")
	if _, err := r.ExchangeContext(context.Background(), query); err != nil {
		t.Fatal(err)
	}
	r.ResetConnection()
	if _, err := r.ExchangeContext(context.Background(), query); err != nil {
		t.Fatal(err)
	}
	if got := c.calls.Load(); got != 1 {
		t.Fatalf("reset discarded cached answer: %d upstream calls", got)
	}
	r.ClearCache()
	if _, err := r.ExchangeContext(context.Background(), query); err != nil {
		t.Fatal(err)
	}
	if c.calls.Load() != 2 || c.resets.Load() != 1 {
		t.Fatal("resolver did not remain reusable after reset")
	}
}

func BenchmarkResetPolicyConnections(b *testing.B) {
	for _, count := range []int{1, 1024, 16384} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			raw := &resetCountingClient{}
			wrapped := clientWithDisableTypes{dnsClient: raw, disableTypes: map[uint16]struct{}{D.TypeAAAA: {}}}
			domains := trie.New[[]dnsClient]()
			for i := range count {
				if err := domains.Insert(fmt.Sprintf("node-%d.policy.test", i), []dnsClient{wrapped}); err != nil {
					b.Fatal(err)
				}
			}
			domains.Optimize()
			r := &Resolver{policy: []dnsPolicy{domainTriePolicy{domains}}}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				r.ResetConnection()
			}
			b.ReportMetric(float64(raw.resets.Load())/float64(b.N), "resets/op")
		})
	}
}
