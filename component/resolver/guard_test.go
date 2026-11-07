package resolver

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func refuseNames(t *testing.T) {
	t.Helper()
	previous := LookupGuard
	LookupGuard = func(host string, _ Resolver) error {
		if strings.Contains(strings.ToLower(host), "refused.example") {
			return errors.New("refused")
		}
		return nil
	}
	t.Cleanup(func() { LookupGuard = previous })
}

func TestCheckNameFollowsTheGuard(t *testing.T) {
	previous := LookupGuard
	LookupGuard = nil
	t.Cleanup(func() { LookupGuard = previous })
	if err := CheckName("a.refused.example"); err != nil {
		t.Fatalf("no guard refused a name: %v", err)
	}
	refuseNames(t)
	if err := CheckName("a.refused.example."); err == nil {
		t.Fatal("the guard's refusal was lost")
	}
	if err := CheckName("public.example."); err != nil {
		t.Fatalf("a public name was refused: %v", err)
	}
}

func TestMessageRefusedReadsEveryNameInAMessage(t *testing.T) {
	header := func(name string, kind uint16) dns.RR_Header {
		return dns.RR_Header{Name: name, Rrtype: kind, Class: dns.ClassINET, Ttl: 60}
	}
	const refused = "a.refused.example."
	const public = "public.example."
	publicA := &dns.A{Hdr: header(public, dns.TypeA), A: net.IPv4(192, 0, 2, 1).To4()}
	message := func(answer ...dns.RR) *dns.Msg {
		msg := new(dns.Msg)
		msg.SetQuestion(public, dns.TypeA)
		msg.Answer = answer
		return msg
	}
	refuseNames(t)
	for name, msg := range map[string]*dns.Msg{
		"owner": message(&dns.A{Hdr: header(refused, dns.TypeA), A: net.IPv4(192, 0, 2, 1).To4()}),
		"cname": message(&dns.CNAME{Hdr: header(public, dns.TypeCNAME), Target: refused}, publicA),
		"dname": message(&dns.DNAME{Hdr: header(public, dns.TypeDNAME), Target: refused}),
		"ptr":   message(&dns.PTR{Hdr: header(public, dns.TypePTR), Ptr: refused}),
		"ns":    message(&dns.NS{Hdr: header(public, dns.TypeNS), Ns: refused}),
		"mx":    message(&dns.MX{Hdr: header(public, dns.TypeMX), Mx: refused}),
		"srv":   message(&dns.SRV{Hdr: header(public, dns.TypeSRV), Target: refused}),
		"https": message(&dns.HTTPS{SVCB: dns.SVCB{Hdr: header(public, dns.TypeHTTPS), Target: refused}}),
		"soa":   message(&dns.SOA{Hdr: header(public, dns.TypeSOA), Ns: refused, Mbox: public}),
	} {
		if !MessageRefused(msg) {
			t.Errorf("%s: a refused name went unnoticed", name)
		}
	}
	question := new(dns.Msg)
	question.SetQuestion(refused, dns.TypeA)
	if !MessageRefused(question) {
		t.Error("a refused question went unnoticed")
	}
	authority := message()
	authority.Ns = []dns.RR{&dns.NS{Hdr: header(public, dns.TypeNS), Ns: refused}}
	if !MessageRefused(authority) {
		t.Error("the authority section went unread")
	}
	extra := message()
	extra.Extra = []dns.RR{&dns.A{Hdr: header(refused, dns.TypeA), A: net.IPv4(192, 0, 2, 1).To4()}}
	if !MessageRefused(extra) {
		t.Error("the additional section went unread")
	}
	clean := message(&dns.CNAME{Hdr: header(public, dns.TypeCNAME), Target: "other.example."}, publicA)
	clean.SetEdns0(1232, false)
	if MessageRefused(clean) {
		t.Error("a public answer was refused")
	}
	LookupGuard = nil
	if MessageRefused(question) {
		t.Error("no guard refused a message")
	}
}
