package dns

import (
	"context"
	"errors"
	"net"
	"net/netip"

	C "github.com/metacubex/mihomo/constant"
	"sync"
	"testing"
	"time"

	D "github.com/miekg/dns"
)

type fallbackTestClient struct {
	started chan struct{}
	release <-chan struct{}
	once    sync.Once
	answer  string
	err     error
}

func (c *fallbackTestClient) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	c.once.Do(func() { close(c.started) })
	if c.release != nil {
		select {
		case <-c.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if c.err != nil {
		return nil, c.err
	}
	reply := new(D.Msg)
	reply.SetReply(m)
	if c.answer != "" {
		reply.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: m.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}, A: net.ParseIP(c.answer).To4()}}
	}
	return reply, nil
}
func (c *fallbackTestClient) Address() string  { return "memory-test" }
func (c *fallbackTestClient) ResetConnection() {}
func startFallbackExchange(t *testing.T, r *Resolver) (context.Context, <-chan result) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	done := make(chan result, 1)
	go func() {
		msg, err := r.ipExchange(ctx, new(D.Msg).SetQuestion("fallback-test.invalid.", D.TypeA))
		done <- result{Msg: msg, Error: err}
	}()
	return ctx, done
}
func requireDNSResult(t *testing.T, ctx context.Context, done <-chan result, want string) {
	t.Helper()
	select {
	case got := <-done:
		ips := msgToIP(got.Msg)
		if got.Error != nil || len(ips) != 1 || ips[0].String() != want {
			t.Fatalf("answer=%v error=%v, want %s", ips, got.Error, want)
		}
	case <-ctx.Done():
		t.Fatal("DNS exchange did not finish")
	}
}
func TestFallbackStartsBeforeMainFinishes(t *testing.T) {
	for _, mainFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "main-accepted", true: "main-error"}[mainFails], func(t *testing.T) {
			release := make(chan struct{})
			main := &fallbackTestClient{started: make(chan struct{}), release: release, answer: "192.0.2.1"}
			if mainFails {
				main.err = errors.New("main failed")
			}
			fallback := &fallbackTestClient{started: make(chan struct{}), answer: "192.0.2.2"}
			ctx, done := startFallbackExchange(t, &Resolver{main: []dnsClient{main}, fallback: []dnsClient{fallback}})
			select {
			case <-fallback.started:
			case <-time.After(time.Second):
				t.Error("fallback waited for the main response")
			}
			close(release)
			want := "192.0.2.1"
			if mainFails {
				want = "192.0.2.2"
			}
			requireDNSResult(t, ctx, done, want)
		})
	}
}

type fallbackIPMatcher struct{}

func (fallbackIPMatcher) MatchIp(ip netip.Addr) bool { return ip.String() == "192.0.2.1" }

type fallbackDomainMatcher struct{}

func (fallbackDomainMatcher) MatchDomain(host string) bool { return host == "fallback-test.invalid" }

func TestLazyFallbackWaitsForMainAndOnlyQueriesWhenNeeded(t *testing.T) {
	for _, mode := range []string{"accepted", "error", "filtered", "empty"} {
		t.Run(mode, func(t *testing.T) {
			release := make(chan struct{})
			main := &fallbackTestClient{started: make(chan struct{}), release: release, answer: "192.0.2.1"}
			fallback := &fallbackTestClient{started: make(chan struct{}), answer: "192.0.2.2"}
			r := &Resolver{main: []dnsClient{main}, fallback: []dnsClient{fallback}, fallbackLazyQuery: true}
			switch mode {
			case "error":
				main.err = errors.New("main failed")
			case "filtered":
				r.fallbackIPFilters = []C.IpMatcher{fallbackIPMatcher{}}
			case "empty":
				main.answer = ""
			}
			ctx, done := startFallbackExchange(t, r)
			select {
			case <-main.started:
			case <-ctx.Done():
				t.Fatal("main query did not start")
			}
			select {
			case <-fallback.started:
				t.Error("lazy fallback started before the main response")
			case <-time.After(50 * time.Millisecond):
			}
			close(release)
			want := "192.0.2.2"
			if mode == "accepted" {
				want = "192.0.2.1"
			}
			requireDNSResult(t, ctx, done, want)
			if mode == "accepted" {
				select {
				case <-fallback.started:
					t.Error("accepted main response triggered lazy fallback")
				default:
				}
			} else {
				select {
				case <-fallback.started:
				default:
					t.Error("missing fallback query")
				}
			}
		})
	}
}

func TestDNSPolicyAndFallbackDomainBypassOtherServers(t *testing.T) {
	for _, lazy := range []bool{false, true} {
		for _, policy := range []bool{false, true} {
			main := &fallbackTestClient{started: make(chan struct{}), answer: "192.0.2.1"}
			fallback := &fallbackTestClient{started: make(chan struct{}), answer: "192.0.2.2"}
			selected := &fallbackTestClient{started: make(chan struct{}), answer: "192.0.2.3"}
			r := &Resolver{main: []dnsClient{main}, fallback: []dnsClient{fallback}, fallbackLazyQuery: lazy, fallbackDomainFilters: []C.DomainMatcher{fallbackDomainMatcher{}}}
			want := "192.0.2.2"
			if policy {
				r.policy = []dnsPolicy{domainMatcherPolicy{matcher: fallbackDomainMatcher{}, dnsClients: []dnsClient{selected}}}
				want = "192.0.2.3"
			}
			ctx, done := startFallbackExchange(t, r)
			requireDNSResult(t, ctx, done, want)
			select {
			case <-main.started:
				t.Fatal("bypassed main server was queried")
			default:
			}
			if policy {
				select {
				case <-fallback.started:
					t.Fatal("policy match triggered fallback query")
				default:
				}
			}
		}
	}
}

func TestEmptyFallbackKeepsMainResultAndErrors(t *testing.T) {
	for _, fallback := range [][]dnsClient{nil, {}} {
		for _, fail := range []bool{false, true} {
			main := &fallbackTestClient{started: make(chan struct{}), answer: "192.0.2.1"}
			failure := errors.New("fixture main failure")
			if fail {
				main.err = failure
			}
			r := &Resolver{main: []dnsClient{main}, fallback: fallback}
			ctx, done := startFallbackExchange(t, r)
			if !fail {
				requireDNSResult(t, ctx, done, "192.0.2.1")
				continue
			}
			select {
			case got := <-done:
				if !errors.Is(got.Error, failure) {
					t.Fatalf("lost main failure: %v", got.Error)
				}
			case <-ctx.Done():
				t.Fatal("DNS exchange did not finish")
			}
		}
	}
}

func TestFallbackResolverReceivesLazyConfiguration(t *testing.T) {
	for _, lazy := range []bool{false, true} {
		rs := NewResolver(Config{Main: []NameServer{{Addr: "192.0.2.1:53"}}, Fallback: []NameServer{{Addr: "192.0.2.2:53"}}, FallbackLazyQuery: lazy})
		if rs.Resolver.fallbackLazyQuery != lazy {
			t.Fatalf("lazy config was lost: %t", lazy)
		}
		rs.Resolver.ResetConnection()
	}
}
