package easytier

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"

	"github.com/easytier/easytier/easytier-go/platform"
	D "github.com/miekg/dns"
)

type testDNSResolver struct {
	resolver.Resolver
	exchange func(context.Context, *D.Msg) (*D.Msg, error)
}

func (*testDNSResolver) Invalid() bool { return true }

func (r *testDNSResolver) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	return r.exchange(ctx, m)
}

func TestDNSRecordsUseMihomoResolver(t *testing.T) {
	oldProxy, oldDefault := resolver.ProxyServerHostResolver.Load(), net.DefaultResolver
	t.Cleanup(func() {
		resolver.ProxyServerHostResolver.Store(oldProxy)
		net.DefaultResolver = oldDefault
	})
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			t.Error("net.DefaultResolver was used")
			return nil, errors.New("forbidden resolver")
		},
	}
	resolver.ProxyServerHostResolver.Store(&testDNSResolver{exchange: func(_ context.Context, m *D.Msg) (*D.Msg, error) {
		reply := new(D.Msg).SetReply(m)
		switch m.Question[0].Qtype {
		case D.TypeTXT:
			reply.Answer = []D.RR{&D.TXT{Txt: []string{"ok"}}}
		case D.TypeSRV:
			reply.Answer = []D.RR{&D.SRV{Target: "peer.example.", Port: 11010}}
		}
		return reply, nil
	}})

	txt, err := (DNSResolver{}).LookupTXT(context.Background(), platform.DNSQuery{Host: "example"})
	if err != nil || txt != "ok" {
		t.Fatalf("TXT: %q %v", txt, err)
	}
	srv, err := (DNSResolver{}).LookupSRV(context.Background(), platform.DNSQuery{Host: "example"})
	if err != nil || len(srv) != 1 || srv[0].Target != "peer.example." || srv[0].Port != 11010 {
		t.Fatalf("SRV: %v %v", srv, err)
	}
}

func TestUDPBindPreservesWildcardPort(t *testing.T) {
	_, address := udpBind(platform.UDPBindOptions{LocalAddr: &net.UDPAddr{Port: 45678}})
	_, port, err := net.SplitHostPort(address)
	if err != nil || port != "45678" {
		t.Fatalf("%s: %v", address, err)
	}
}

type forbiddenDialer struct{}

func (forbiddenDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	panic("unexpected proxy session")
}

func (forbiddenDialer) ListenPacket(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
	panic("unexpected proxy socket")
}

func TestListenTCPInternalAllowedThroughProxyDialer(t *testing.T) {
	factory := SocketFactory{Dialer: forbiddenDialer{}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	listener, err := factory.ListenTCP(ctx, platform.TCPListenOptions{
		Bind:    platform.TCPBindOptions{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}},
		Purpose: platform.TCPListenProxyNAT,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if _, err := factory.ListenTCP(ctx, platform.TCPListenOptions{
		Bind:    platform.TCPBindOptions{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}},
		Purpose: platform.TCPListenDirect,
	}); err == nil {
		t.Fatal("external listener through proxy must fail")
	}
}

func TestRawDNSQueriesAskTheGuardFirst(t *testing.T) {
	oldProxy, oldGuard := resolver.ProxyServerHostResolver.Load(), resolver.LookupGuard
	t.Cleanup(func() {
		resolver.ProxyServerHostResolver.Store(oldProxy)
		resolver.LookupGuard = oldGuard
	})
	var asked []string
	resolver.ProxyServerHostResolver.Store(&testDNSResolver{exchange: func(_ context.Context, m *D.Msg) (*D.Msg, error) {
		asked = append(asked, m.Question[0].Name)
		reply := new(D.Msg).SetReply(m)
		reply.Answer = []D.RR{&D.TXT{
			Hdr: D.RR_Header{Name: m.Question[0].Name, Rrtype: D.TypeTXT, Class: D.ClassINET, Ttl: 60},
			Txt: []string{"value"},
		}}
		return reply, nil
	}})
	refusal := errors.New("refused")
	resolver.LookupGuard = func(host string, _ resolver.Resolver) error {
		if host == "a.refused.example" || host == "a.refused.example." {
			return refusal
		}
		return nil
	}
	ctx := context.Background()
	if _, err := (DNSResolver{}).LookupTXT(ctx, platform.DNSQuery{Host: "a.refused.example"}); !errors.Is(err, refusal) {
		t.Fatalf("TXT = %v, want the refusal", err)
	}
	if _, err := (DNSResolver{}).LookupSRV(ctx, platform.DNSQuery{Host: "a.refused.example"}); !errors.Is(err, refusal) {
		t.Fatalf("SRV = %v, want the refusal", err)
	}
	if len(asked) != 0 {
		t.Fatalf("refused names went out: %v", asked)
	}
	if got, err := (DNSResolver{}).LookupTXT(ctx, platform.DNSQuery{Host: "public.example"}); err != nil || got != "value" {
		t.Fatalf("a public name = %q, %v", got, err)
	}
	resolver.LookupGuard = nil
	if _, err := (DNSResolver{}).LookupTXT(ctx, platform.DNSQuery{Host: "a.refused.example"}); err != nil {
		t.Fatalf("no guard refused a name: %v", err)
	}
}
