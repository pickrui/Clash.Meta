package dns

import (
	"context"
	"errors"
	"testing"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/trie"
	icontext "github.com/metacubex/mihomo/context"
	D "github.com/miekg/dns"
)

func TestServiceEDNSResponse(t *testing.T) {
	for _, tc := range []struct {
		name                            string
		requestOPT, dnssec, responseOPT bool
	}{
		{"plain", false, false, false},
		{"edns", true, false, false},
		{"dnssec", true, true, false},
		{"existing", true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query := new(D.Msg).SetQuestion("example.test.", D.TypeA)
			if tc.requestOPT {
				query.SetEdns0(4096, tc.dnssec)
			}
			service := &Service{handler: func(_ *icontext.DNSContext, q *D.Msg) (*D.Msg, error) {
				reply := new(D.Msg).SetReply(q)
				if tc.responseOPT {
					reply.SetEdns0(1400, false)
				}
				return reply, nil
			}}
			reply, err := service.ServeMsg(context.Background(), query)
			if err != nil {
				t.Fatal(err)
			}
			opt := reply.IsEdns0()
			if !tc.requestOPT {
				if opt != nil {
					t.Fatal("unexpected OPT")
				}
				return
			}
			if opt == nil {
				t.Fatal("missing response OPT")
			}
			wantSize, wantDO := uint16(1232), tc.dnssec
			if tc.responseOPT {
				wantSize, wantDO = 1400, false
			}
			if opt.UDPSize() != wantSize || opt.Do() != wantDO {
				t.Fatalf("OPT: %+v", opt)
			}
			if len(reply.Extra) != 1 {
				t.Fatal("duplicate OPT")
			}
			if query.IsEdns0().UDPSize() != 4096 {
				t.Fatal("request was modified")
			}
		})
	}
}

func TestServicePreservesErrorsAndRejectsEmptyQuestion(t *testing.T) {
	failure := errors.New("lookup failed")
	called := false
	service := &Service{handler: func(_ *icontext.DNSContext, _ *D.Msg) (*D.Msg, error) { called = true; return nil, failure }}
	if _, err := service.ServeMsg(context.Background(), new(D.Msg)); err == nil || called {
		t.Fatal("empty question reached handler")
	}
	query := new(D.Msg).SetQuestion("example.test.", D.TypeA).SetEdns0(1232, true)
	if reply, err := service.ServeMsg(context.Background(), query); reply != nil || !errors.Is(err, failure) {
		t.Fatalf("got %v, %v", reply, err)
	}
}

func TestHostsCNAMEAnswersWithoutMutatingRequest(t *testing.T) {
	old := resolver.DefaultHosts
	t.Cleanup(func() { resolver.DefaultHosts = old })
	resolver.DefaultHosts = resolver.NewHosts(trie.New[resolver.HostValue]())
	if err := resolver.DefaultHosts.Insert("alias.example.test", resolver.HostValue{IsDomain: true, Domain: "target.example.test"}); err != nil {
		t.Fatal(err)
	}
	handler := withHosts(nil)(func(_ *icontext.DNSContext, _ *D.Msg) (*D.Msg, error) {
		t.Fatal("hosts lookup reached upstream")
		return nil, nil
	})
	query := new(D.Msg).SetQuestion("alias.example.test.", D.TypeCNAME)
	reply, err := handler(icontext.NewDNSContext(context.Background()), query)
	if err != nil {
		t.Fatal(err)
	}
	if len(query.Answer) != 0 {
		t.Fatal("request was modified")
	}
	if len(reply.Answer) != 1 {
		t.Fatalf("CNAME answers: %v", reply.Answer)
	}
	cname, ok := reply.Answer[0].(*D.CNAME)
	if !ok || cname.Target != "target.example.test." || cname.Hdr.Name != query.Question[0].Name {
		t.Fatalf("bad CNAME: %v", reply.Answer)
	}
	if !reply.Response || reply.Id != query.Id {
		t.Fatal("response header was not preserved")
	}
}
