package dns

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/trie"
	D "github.com/miekg/dns"
)

func useClearResolvers(t *testing.T, primary, system resolver.Resolver) {
	t.Helper()
	previous, previousSystem := resolver.DefaultResolver, resolver.SystemResolver
	resolver.DefaultResolver, resolver.SystemResolver = primary, system
	t.Cleanup(func() {
		resolver.DefaultResolver, resolver.SystemResolver = previous, previousSystem
		answeredBy.Clear()
	})
}

func TestClearAllCoversCachesPoliciesAndSystemResolver(t *testing.T) {
	for _, algorithm := range []string{"lru", "arc"} {
		t.Run(algorithm, func(t *testing.T) {
			recordQueries(t)
			roots := make([]*Resolver, 5)
			counters := make([]*resetCountingClient, 5)
			for i := range roots {
				counters[i] = &resetCountingClient{answeringClient: answeringClient{address: fmt.Sprint(i), ip: "192.0.2.1"}}
				roots[i] = NewResolverFromClient(counters[i])
				roots[i].cache = (Config{CacheAlgorithm: algorithm}).newCache()
				t.Cleanup(roots[i].CloseQueries)
				if _, err := roots[i].LookupIPv4(context.Background(), "cached.example"); err != nil {
					t.Fatal(err)
				}
			}
			main, proxy, direct, bootstrap, system := roots[0], roots[1], roots[2], roots[3], roots[4]
			main.defaultResolver, proxy.defaultResolver, direct.defaultResolver = bootstrap, bootstrap, bootstrap
			policyOnly := &resetCountingClient{}
			wrapped := clientWithDisableTypes{dnsClient: clientWithEdns0Subnet{dnsClient: counters[0]}}
			domains := trie.New[[]dnsClient]()
			if err := domains.Insert("policy.example", []dnsClient{wrapped, policyOnly}); err != nil {
				t.Fatal(err)
			}
			domains.Optimize()
			main.policy = []dnsPolicy{domainTriePolicy{domains}, domainMatcherPolicy{matcher: fallbackDomainMatcher{}, dnsClients: []dnsClient{wrapped, policyOnly}}}
			main.fallback = []dnsClient{wrapped}
			clock := newSystemClient()
			clock.lastFlush = time.Now()
			var nonComparable atomic.Int64
			system.main = append(system.main, clock, nil, (*resetCountingClient)(nil),
				nonComparableResetClient{state: []byte{1}, resets: &nonComparable})
			useClearResolvers(t, Resolvers{Resolver: main, ProxyResolver: proxy, DirectResolver: direct}, system)

			ClearAll()

			if !clock.lastFlush.IsZero() || policyOnly.resets.Load() != 1 || nonComparable.Load() != 1 {
				t.Fatal("system state or policy-only clients were not reset")
			}
			system.main = system.main[:1]
			main.fallback = nil
			q := dnsQuestion("cached.example").Question[0]
			for i, r := range roots {
				if _, _, found := getMsgFromCache(r.cache, q); found {
					t.Errorf("resolver %d kept its cache", i)
				}
				if _, found := answeredBy.Get(answeredByKey(r, q)); found {
					t.Errorf("resolver %d kept its answer origin", i)
				}
				if counters[i].resets.Load() != 1 {
					t.Errorf("resolver %d reset %d times", i, counters[i].resets.Load())
				}
				if _, err := r.LookupIPv4(context.Background(), "cached.example"); err != nil {
					t.Fatal(err)
				}
				if counters[i].calls.Load() != 2 {
					t.Errorf("resolver %d did not query again", i)
				}
			}
		})
	}
}

func TestClearAllHandlesStandaloneAndNilRoots(t *testing.T) {
	c := &resetCountingClient{}
	r := NewResolverFromClient(c)
	useClearResolvers(t, r, &Resolvers{Resolver: r, ProxyResolver: r})
	ClearAll()
	if c.resets.Load() != 1 {
		t.Fatal("shared standalone resolver reset more than once")
	}
	resolver.DefaultResolver, resolver.SystemResolver = (*Resolver)(nil), (*Resolvers)(nil)
	ClearAll()
}

type delayedClearClient struct {
	calls   atomic.Int64
	entered chan struct{}
	release chan struct{}
}

func (c *delayedClearClient) Address() string  { return "fixture" }
func (c *delayedClearClient) ResetConnection() {}
func (c *delayedClearClient) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	call := c.calls.Add(1)
	if call == 1 {
		close(c.entered)
		select {
		case <-c.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return (&answeringClient{ip: fmt.Sprintf("192.0.2.%d", call)}).ExchangeContext(ctx, m)
}

func TestClearAllDoesNotJoinOrCachePreClearQueries(t *testing.T) {
	recordQueries(t)
	client := &delayedClearClient{entered: make(chan struct{}), release: make(chan struct{})}
	r := NewResolverFromClient(client)
	defer r.CloseQueries()
	useClearResolvers(t, Resolvers{Resolver: r}, nil)
	old := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() { _, err := r.LookupIPv4(ctx, "pending.example"); old <- err }()
	<-client.entered
	released := false
	defer func() {
		if !released {
			close(client.release)
			<-old
		}
	}()
	ClearAll()
	freshCtx, freshCancel := context.WithTimeout(ctx, time.Second)
	defer freshCancel()
	fresh, err := r.LookupIPv4(freshCtx, "pending.example")
	if err != nil || len(fresh) != 1 || fresh[0].String() != "192.0.2.2" {
		t.Fatalf("new query joined the previous exchange: %v %v", fresh, err)
	}
	ClearAll()
	close(client.release)
	released = true
	if err := <-old; err != nil {
		t.Fatal(err)
	}
	q := dnsQuestion("pending.example").Question[0]
	if _, _, hit := getMsgFromCache(r.cache, q); hit {
		t.Fatal("old query restored the cleared cache")
	}
	if _, hit := answeredBy.Get(answeredByKey(r, q)); hit {
		t.Fatal("old query restored cleared answer metadata")
	}
	if _, err := r.LookupIPv4(ctx, "pending.example"); err != nil {
		t.Fatal(err)
	}
	if client.calls.Load() != 3 {
		t.Fatal("resolver did not remain reusable")
	}
}
