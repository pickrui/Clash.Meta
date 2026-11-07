package dns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/component/fakeip"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"

	D "github.com/miekg/dns"
)

type answeringResolver struct {
	resolver.Resolver
	asked  []string
	answer func(q D.Question) []D.RR
}

func (r *answeringResolver) ExchangeContext(_ context.Context, m *D.Msg) (*D.Msg, error) {
	r.asked = append(r.asked, m.Question[0].Name)
	reply := new(D.Msg).SetReply(m)
	reply.Answer = r.answer(m.Question[0])
	return reply, nil
}

func addressOf(q D.Question) []D.RR {
	return []D.RR{&D.A{
		Hdr: D.RR_Header{Name: q.Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60},
		A:   net.IPv4(192, 0, 2, 1).To4(),
	}}
}

func guardNames(t *testing.T) {
	t.Helper()
	previous := resolver.LookupGuard
	resolver.LookupGuard = func(host string, _ resolver.Resolver) error {
		if strings.Contains(strings.ToLower(host), "refused.example") {
			return errors.New("refused")
		}
		return nil
	}
	t.Cleanup(func() { resolver.LookupGuard = previous })
}

func ask(t *testing.T, service *Service, name string, kind uint16) *D.Msg {
	t.Helper()
	query := new(D.Msg).SetQuestion(name, kind)
	reply, err := service.ServeMsg(context.Background(), query)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return reply
}

func fakeIPEnhancer(t *testing.T) *ResolverEnhancer {
	t.Helper()
	pool, err := fakeip.New(fakeip.Options{IPNet: netip.MustParsePrefix("198.18.0.1/24"), Size: 16})
	if err != nil {
		t.Fatal(err)
	}
	return NewEnhancer(EnhancerConfig{
		EnhancedMode:  C.DNSFakeIP,
		FakeIPPool:    pool,
		FakeIPSkipper: &fakeip.Skipper{},
		FakeIPTTL:     1,
	})
}

func TestLocalQueriesRefuseWhatTheGuardRefuses(t *testing.T) {
	guardNames(t)
	for name, enhancer := range map[string]*ResolverEnhancer{
		"normal":  NewEnhancer(EnhancerConfig{EnhancedMode: C.DNSNormal}),
		"fake-ip": fakeIPEnhancer(t),
	} {
		t.Run(name, func(t *testing.T) {
			upstream := &answeringResolver{answer: addressOf}
			service := NewService(upstream, enhancer)
			for _, host := range []string{"a.refused.example.", "A.Refused.Example."} {
				for _, kind := range []uint16{D.TypeA, D.TypeAAAA, D.TypeTXT, D.TypeHTTPS} {
					reply := ask(t, service, host, kind)
					if reply.Rcode != D.RcodeRefused || len(reply.Answer) != 0 {
						t.Fatalf("%s: rcode %d, answer %v", host, reply.Rcode, reply.Answer)
					}
				}
			}
			if len(upstream.asked) != 0 {
				t.Fatalf("refused names went upstream: %v", upstream.asked)
			}
			reply := ask(t, service, "public.example.", D.TypeA)
			if reply.Rcode != D.RcodeSuccess || len(reply.Answer) != 1 {
				t.Fatalf("a public name: rcode %d, answer %v", reply.Rcode, reply.Answer)
			}
		})
	}
}

func TestLocalQueriesRefuseAnAnswerNamingARefusedHost(t *testing.T) {
	guardNames(t)
	upstream := &answeringResolver{answer: func(q D.Question) []D.RR {
		switch q.Name {
		case "alias.example.":
			return append([]D.RR{&D.CNAME{
				Hdr:    D.RR_Header{Name: q.Name, Rrtype: D.TypeCNAME, Class: D.ClassINET, Ttl: 60},
				Target: "a.refused.example.",
			}}, addressOf(q)...)
		case "1.2.0.192.in-addr.arpa.":
			return []D.RR{&D.PTR{
				Hdr: D.RR_Header{Name: q.Name, Rrtype: D.TypePTR, Class: D.ClassINET, Ttl: 60},
				Ptr: "a.refused.example.",
			}}
		}
		return addressOf(q)
	}}
	service := NewService(upstream, NewEnhancer(EnhancerConfig{EnhancedMode: C.DNSNormal}))
	for name, kind := range map[string]uint16{"alias.example.": D.TypeA, "1.2.0.192.in-addr.arpa.": D.TypePTR} {
		reply := ask(t, service, name, kind)
		if reply.Rcode != D.RcodeRefused || len(reply.Answer) != 0 {
			t.Fatalf("%s: rcode %d, answer %v", name, reply.Rcode, reply.Answer)
		}
	}
}

func TestHostsCannotRenameAQueryPastTheGuard(t *testing.T) {
	guardNames(t)
	previous := resolver.DefaultHosts.Load()
	t.Cleanup(func() { resolver.DefaultHosts.Store(previous) })
	tree := trie.New[resolver.HostValue]()
	renamed, err := resolver.NewHostValueByDomain("a.refused.example")
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.Insert("alias.example", renamed); err != nil {
		t.Fatal(err)
	}
	resolver.DefaultHosts.Store(resolver.NewHosts(tree))
	upstream := &answeringResolver{answer: addressOf}
	service := NewService(upstream, NewEnhancer(EnhancerConfig{EnhancedMode: C.DNSNormal, UseHosts: true}))
	reply := ask(t, service, "alias.example.", D.TypeA)
	if reply.Rcode != D.RcodeRefused || len(reply.Answer) != 0 {
		t.Fatalf("rcode %d, answer %v", reply.Rcode, reply.Answer)
	}
	if len(upstream.asked) != 0 {
		t.Fatalf("the renamed query went upstream: %v", upstream.asked)
	}
}

func TestLocalQueriesWithoutAGuardAreUntouched(t *testing.T) {
	previous := resolver.LookupGuard
	resolver.LookupGuard = nil
	t.Cleanup(func() { resolver.LookupGuard = previous })
	upstream := &answeringResolver{answer: addressOf}
	service := NewService(upstream, NewEnhancer(EnhancerConfig{EnhancedMode: C.DNSNormal}))
	reply := ask(t, service, "a.refused.example.", D.TypeA)
	if reply.Rcode != D.RcodeSuccess || len(reply.Answer) != 1 || len(upstream.asked) != 1 {
		t.Fatalf("rcode %d, answer %v, asked %v", reply.Rcode, reply.Answer, upstream.asked)
	}
}
