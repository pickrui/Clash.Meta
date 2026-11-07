package route

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/miekg/dns"
)

type answeringResolver struct {
	resolver.Resolver
	asked  []string
	answer func(name string) []dns.RR
}

func (r *answeringResolver) ExchangeContext(_ context.Context, m *dns.Msg) (*dns.Msg, error) {
	r.asked = append(r.asked, m.Question[0].Name)
	reply := new(dns.Msg).SetReply(m)
	reply.Answer = r.answer(m.Question[0].Name)
	return reply, nil
}

func queryDNSFor(t *testing.T, name string) (map[string]any, string) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/query?name="+name, nil)
	response := httptest.NewRecorder()
	queryDNS(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("%s: status %d", name, response.Code)
	}
	body := response.Body.String()
	var decoded map[string]any
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded, body
}

func TestDNSQueryRefusesWhatTheGuardRefuses(t *testing.T) {
	previousDNS, previousGuard := resolver.DefaultResolver.Load(), resolver.LookupGuard
	t.Cleanup(func() {
		resolver.DefaultResolver.Store(previousDNS)
		resolver.LookupGuard = previousGuard
	})
	upstream := &answeringResolver{answer: func(name string) []dns.RR {
		address := &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IPv4(192, 0, 2, 1).To4(),
		}
		if name != "alias.example." {
			return []dns.RR{address}
		}
		return []dns.RR{&dns.CNAME{
			Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
			Target: "a.refused.example.",
		}, address}
	}}
	resolver.DefaultResolver.Store(upstream)
	resolver.LookupGuard = func(host string, _ resolver.Resolver) error {
		if strings.Contains(host, "refused.example") {
			return errors.New("refused")
		}
		return nil
	}

	got, _ := queryDNSFor(t, "a.refused.example")
	if got["Status"] != float64(dns.RcodeRefused) || got["Answer"] != nil {
		t.Fatalf("a refused name answered %v", got)
	}
	if len(upstream.asked) != 0 {
		t.Fatalf("a refused name went upstream: %v", upstream.asked)
	}

	got, body := queryDNSFor(t, "alias.example")
	if got["Status"] != float64(dns.RcodeRefused) || got["Answer"] != nil {
		t.Fatalf("an answer naming a refused host came back: %v", got)
	}
	if strings.Contains(body, "refused.example") || strings.Contains(body, "192.0.2.1") {
		t.Fatalf("the reply carries the answer: %s", body)
	}

	got, _ = queryDNSFor(t, "public.example")
	if got["Status"] != float64(dns.RcodeSuccess) || got["Answer"] == nil {
		t.Fatalf("a public name answered %v", got)
	}

	resolver.LookupGuard = nil
	got, _ = queryDNSFor(t, "a.refused.example")
	if got["Status"] != float64(dns.RcodeSuccess) || got["Answer"] == nil {
		t.Fatalf("without a guard a name answered %v", got)
	}
}
