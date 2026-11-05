package dns

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	D "github.com/miekg/dns"
)

type lifecycleDNSClient struct {
	answeringClient
	entered chan context.Context
	release chan struct{}
	calls   atomic.Int64
	active  atomic.Int64
}

func (c *lifecycleDNSClient) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	c.calls.Add(1)
	c.active.Add(1)
	defer c.active.Add(-1)
	c.entered <- ctx
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.release:
		return c.answeringClient.ExchangeContext(ctx, m)
	}
}

func waitResolverCondition(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("resolver work did not settle")
		}
		time.Sleep(time.Millisecond)
	}
}

func newLifecycleResolver(t *testing.T) (*Resolver, *lifecycleDNSClient) {
	t.Helper()
	c := &lifecycleDNSClient{
		answeringClient: answeringClient{address: "fixture", ip: "192.0.2.1"},
		entered:         make(chan context.Context, 1024),
		release:         make(chan struct{}),
	}
	r := NewResolverFromClient(c)
	t.Cleanup(func() {
		r.CloseQueries()
		select {
		case <-c.release:
		default:
			close(c.release)
		}
		waitResolverCondition(t, func() bool { return c.active.Load() == 0 })
	})
	return r, c
}

func dnsQuestion(name string) *D.Msg {
	m := new(D.Msg)
	m.SetQuestion(name+".", D.TypeA)
	return m
}

func awaitDNSStart(t *testing.T, c *lifecycleDNSClient) context.Context {
	t.Helper()
	select {
	case ctx := <-c.entered:
		return ctx
	case <-time.After(time.Second):
		t.Fatal("upstream query did not start")
		return nil
	}
}

func seedStaleDNS(r *Resolver, m *D.Msg) {
	answer, _ := (&answeringClient{ip: "192.0.2.1"}).ExchangeContext(context.Background(), m)
	r.cache.SetWithExpire(m.Question[0].String(), answer, time.Now().Add(-time.Minute))
}

func TestResolverCloseQueriesStopsActiveWork(t *testing.T) {
	for _, stale := range []bool{false, true} {
		t.Run(fmt.Sprintf("stale=%v", stale), func(t *testing.T) {
			r, c := newLifecycleResolver(t)
			const count = 32
			var callers sync.WaitGroup
			for i := range count {
				m := dnsQuestion(fmt.Sprintf("owned-%d.test", i))
				if stale {
					seedStaleDNS(r, m)
				}
				callers.Go(func() {
					_, _ = r.ExchangeContext(context.Background(), m)
				})
			}
			for range count {
				awaitDNSStart(t, c)
			}
			before := c.active.Load()
			start := time.Now()
			r.CloseQueries()
			waitResolverCondition(t, func() bool { return c.active.Load() == 0 })
			callers.Wait()
			t.Logf("close canceled %d active upstream queries in %s", before, time.Since(start))
			for range 32 {
				if _, err := r.ExchangeContext(context.Background(), dnsQuestion("late.test")); !errors.Is(err, context.Canceled) {
					t.Fatalf("closed resolver accepted a new query: %v", err)
				}
			}
			if got := c.calls.Load(); got != count {
				t.Fatalf("closed resolver retried upstream: calls=%d, want %d", got, count)
			}
		})
	}
}

func TestResolverCancellationAndResetKeepSharedQuery(t *testing.T) {
	r, c := newLifecycleResolver(t)
	impatient, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := dnsQuestion("shared.test")
	done := make(chan error, 1)
	go func() { _, err := r.ExchangeContext(impatient, m); done <- err }()
	upstream := awaitDNSStart(t, c)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("caller cancellation: %v", err)
	}
	r.ResetConnection()
	if err := upstream.Err(); err != nil {
		t.Fatalf("caller cancellation or reset killed the shared query: %v", err)
	}
	m.Question[0].Name = "changed-after-return.test."
	close(c.release)
	answer, err := r.ExchangeContext(context.Background(), dnsQuestion("shared.test"))
	if err != nil || answer == nil || answer.Question[0].Name != "shared.test." {
		t.Fatalf("shared query lost its owned question: answer=%v err=%v", answer, err)
	}
	if c.calls.Load() != 1 {
		t.Fatalf("cancellation restarted a shared query: %d calls", c.calls.Load())
	}
}

func TestResolverCloseBeforeUseAndAfterCacheHit(t *testing.T) {
	for _, warm := range []bool{false, true} {
		t.Run(fmt.Sprintf("warm=%v", warm), func(t *testing.T) {
			r, c := newLifecycleResolver(t)
			close(c.release)
			m := dnsQuestion("cached.test")
			if warm {
				if _, err := r.ExchangeContext(context.Background(), m); err != nil {
					t.Fatal(err)
				}
			}
			calls := c.calls.Load()
			r.CloseQueries()
			r.CloseQueries()
			r.ResetConnection()
			if _, err := r.ExchangeContext(context.Background(), m); !errors.Is(err, context.Canceled) {
				t.Fatalf("closed resolver revived: %v", err)
			}
			if c.calls.Load() != calls {
				t.Fatal("closing before first use or resetting after close restarted a query")
			}
		})
	}
}

func TestResolverCloseConcurrentWithQueries(t *testing.T) {
	r, c := newLifecycleResolver(t)
	var callers sync.WaitGroup
	for i := range 64 {
		callers.Go(func() {
			_, _ = r.ExchangeContext(context.Background(), dnsQuestion(fmt.Sprintf("racing-%d.test", i)))
		})
		callers.Go(r.CloseQueries)
	}
	callers.Wait()
	waitResolverCondition(t, func() bool { return c.active.Load() == 0 })
	if _, err := r.ExchangeContext(context.Background(), dnsQuestion("after-race.test")); !errors.Is(err, context.Canceled) {
		t.Fatalf("concurrent first use revived a closed resolver: %v", err)
	}
}

func TestResolverGroupClosesEveryOwnedResolver(t *testing.T) {
	main, _ := newLifecycleResolver(t)
	proxy, _ := newLifecycleResolver(t)
	direct, _ := newLifecycleResolver(t)
	bootstrap, _ := newLifecycleResolver(t)
	main.defaultResolver = bootstrap
	Resolvers{Resolver: main, ProxyResolver: proxy, DirectResolver: direct}.CloseQueries()
	for _, r := range []*Resolver{main, proxy, direct, bootstrap} {
		if _, err := r.ExchangeContext(context.Background(), dnsQuestion("closed-group.test")); !errors.Is(err, context.Canceled) {
			t.Fatalf("resolver group left a member open: %v", err)
		}
	}
	Resolvers{}.CloseQueries()
}

func TestResolverRefreshBurstResources(t *testing.T) {
	r, c := newLifecycleResolver(t)
	m := dnsQuestion("stale-burst.test")
	seedStaleDNS(r, m)
	if _, err := r.ExchangeContext(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	awaitDNSStart(t, c)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	workersBefore := runtime.NumGoroutine()
	const count = 512
	for range count {
		answer, err := r.ExchangeContext(context.Background(), m)
		if err != nil || answer.Answer[0].Header().Ttl != 1 {
			t.Fatalf("stale answer stopped being immediately available: %v", err)
		}
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	workers := runtime.NumGoroutine() - workersBefore
	t.Logf("%d stale hits: %+d goroutines, %+d heap bytes, %+d heap objects", count, workers, int64(after.HeapAlloc)-int64(before.HeapAlloc), int64(after.HeapObjects)-int64(before.HeapObjects))
	if workers > 16 || c.calls.Load() != 1 {
		t.Fatalf("duplicate stale hits accumulated refresh workers: workers=%d upstream calls=%d", workers, c.calls.Load())
	}
	close(c.release)
	waitResolverCondition(t, func() bool { return c.active.Load() == 0 })
	waitResolverCondition(t, func() bool {
		_, expire, hit := r.cache.GetWithExpire(m.Question[0].String())
		return hit && expire.After(time.Now())
	})
	answer, err := r.ExchangeContext(context.Background(), m)
	if err != nil || answer.Answer[0].Header().Ttl <= 1 {
		t.Fatalf("refresh did not publish its fresh answer: %v", err)
	}
}

func TestResolverRefreshOwnsQuestionAndCanRunAgain(t *testing.T) {
	r, c := newLifecycleResolver(t)
	m := dnsQuestion("refresh-owned.test")
	seedStaleDNS(r, m)
	if _, err := r.ExchangeContext(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	awaitDNSStart(t, c)
	m.Question[0].Name = "changed-after-cache-hit.test."
	close(c.release)
	original := dnsQuestion("refresh-owned.test")
	waitResolverCondition(t, func() bool {
		_, expire, hit := r.cache.GetWithExpire(original.Question[0].String())
		return hit && expire.After(time.Now())
	})
	answer, err := r.ExchangeContext(context.Background(), original)
	if err != nil || answer.Question[0].Name != original.Question[0].Name {
		t.Fatalf("refresh used caller-owned memory after returning: answer=%v err=%v", answer, err)
	}
	seedStaleDNS(r, original)
	waitResolverCondition(t, func() bool {
		_, _ = r.ExchangeContext(context.Background(), original)
		return c.calls.Load() >= 2
	})
}
