package provider_test

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/rules"
	"github.com/metacubex/mihomo/rules/common"
	RP "github.com/metacubex/mihomo/rules/provider"
)

func classicalIPLines(n int) []string {
	lines := make([]string, n)
	for i := range lines {
		lines[i] = fmt.Sprintf("IP-CIDR,10.%d.%d.0/25,no-resolve", i/256, i%256)
	}
	return lines
}

func TestClassicalIPIndexMatchesLinearScan(t *testing.T) {
	prefixes := []string{
		"10.0.0.129/25", "10.0.0.192/26", "192.0.2.0/25", "192.0.2.128/25",
		"::ffff:198.51.100.9/120", "2001:db8::1/64", "fe80::7/64",
		"::/128", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
		"0.0.0.0/32", "255.255.255.255/32",
	}
	addresses := []string{
		"", "0.0.0.0", "255.255.255.255", "10.0.0.127", "10.0.0.128", "10.0.0.255", "10.0.1.0",
		"192.0.2.0", "192.0.2.255", "192.0.3.0", "198.51.100.9",
		"::", "::1", "::ffff:192.0.2.1", "::ffff:198.51.100.9", "::ffff:198.51.100.9%en0",
		"2001:db8::1", "2001:db8:1::1", "2001:db8::ffff%en0", "fe80::1%en0",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
	}
	for _, format := range []string{"IP-CIDR,%s,no-resolve", "IP-CIDR6,%s,no-resolve", "SRC-IP-CIDR,%s", "IP-CIDR,%s,src"} {
		for _, corpus := range [][]string{prefixes, {"0.0.0.0/0"}, {"::/0"}, {"::ffff:0:0/96"}} {
			lines := make([]string, 64)
			for i := range lines {
				lines[i] = fmt.Sprintf(format, corpus[i%len(corpus)])
			}
			reference, indexed := loadClassical(lines, false), loadClassical(lines, true)
			for _, address := range addresses {
				ip, _ := netip.ParseAddr(address)
				compareClassical(t, reference, indexed, C.Metadata{DstIP: ip})
				compareClassical(t, reference, indexed, C.Metadata{SrcIP: ip})
			}
		}
	}
	for seed := uint64(1); seed <= 8; seed++ {
		rng := rand.New(rand.NewPCG(seed, 2))
		var lines []string
		for run := range 6 {
			for range 64 {
				prefix := fmt.Sprintf("10.%d.%d.7/25", rng.IntN(16), rng.IntN(16))
				if rng.IntN(2) == 0 {
					prefix = fmt.Sprintf("2001:db8:%x::1/64", rng.IntN(32))
				}
				line := "IP-CIDR," + prefix + ",no-resolve"
				if run%2 == 0 {
					line = "SRC-IP-CIDR," + prefix
				}
				lines = append(lines, line)
			}
			lines = append(lines, classicalLines(32)...)
			lines = append(lines, "IP-CIDR,192.0.2.0/24", "PROCESS-NAME,editor")
		}
		reference, indexed := loadClassical(lines, false), loadClassical(lines, true)
		for trial := range 400 {
			m := C.Metadata{
				DstIP: netip.AddrFrom4([4]byte{10, byte(rng.IntN(20)), byte(rng.IntN(20)), byte(rng.IntN(256))}),
				SrcIP: netip.MustParseAddr(fmt.Sprintf("2001:db8:%x::1", rng.IntN(48))),
			}
			if trial%3 == 0 {
				m.SrcIP, m.DstIP = m.DstIP, m.SrcIP
			}
			if trial%5 == 0 {
				m.Host = "host0.example.test"
			}
			compareClassical(t, reference, indexed, m)
		}
	}
}

func TestClassicalIPIndexKeepsResolutionOrder(t *testing.T) {
	lines := classicalIPLines(32)
	lines = append(lines, slices.Repeat([]string{"IP-CIDR,192.0.2.0/24"}, 32)...)
	lines = append(lines, classicalIPLines(32)...)
	for _, finish := range []bool{false, true} {
		s := loadClassical(lines, finish)
		for _, initial := range []string{"10.0.0.1", "198.51.100.1"} {
			m := C.Metadata{DstIP: netip.MustParseAddr(initial)}
			calls := 0
			helper := C.RuleMatchHelper{ResolveIP: func() {
				calls++
				if calls == 16 {
					m.DstIP = netip.MustParseAddr("192.0.2.7")
				}
			}}
			wantCalls := 16
			if initial == "10.0.0.1" {
				wantCalls = 0
			}
			if !s.Match(&m, helper) || calls != wantCalls {
				t.Fatalf("indexed=%v initial=%s: resolve calls=%d, want %d", finish, initial, calls, wantCalls)
			}
		}
		if s.Match(&C.Metadata{}, C.RuleMatchHelper{}) {
			t.Fatal("missing addresses and a nil resolver matched")
		}
	}
}

type classicalIPRewrite struct{ C.Rule }

func (r *classicalIPRewrite) Match(m *C.Metadata, _ C.RuleMatchHelper) (bool, string) {
	m.SrcIP = netip.MustParseAddr("10.0.0.1")
	return false, ""
}

func TestClassicalIPIndexHonorsParserAndMetadataChanges(t *testing.T) {
	parse := func(tp, payload, target string, params []string, subRules map[string][]C.Rule) (C.Rule, error) {
		if payload == "198.51.100.7/32" {
			r, err := common.NewIPCIDR(payload, target, common.WithIPCIDRNoResolve(true))
			return &classicalIPRewrite{Rule: r}, err
		}
		if payload == "198.51.100.8/32" {
			payload = "192.0.2.0/24"
		}
		return rules.ParseRule(tp, payload, target, params, subRules)
	}
	lines := classicalIPLines(32)
	lines = append(lines, "IP-CIDR,198.51.100.7/32,no-resolve")
	for _, line := range classicalIPLines(32) {
		lines = append(lines, strings.Replace(line, "IP-CIDR,", "SRC-IP-CIDR,", 1))
	}
	lines = append(lines, classicalIPLines(32)...)
	lines = append(lines, "IP-CIDR,198.51.100.8/32,no-resolve", "IP-CIDR,invalid,no-resolve")
	s := RP.NewClassicalStrategy(parse)
	for _, line := range lines {
		s.Insert(line)
	}
	s.FinishInsert()
	for _, initial := range []string{"10.0.0.1", "198.51.100.1"} {
		m := C.Metadata{DstIP: netip.MustParseAddr(initial)}
		if !s.Match(&m, C.RuleMatchHelper{}) || m.SrcIP.IsValid() != (initial != "10.0.0.1") {
			t.Fatalf("custom rule side effects changed for %s: %+v", initial, m)
		}
	}
	if s.Count() != len(lines)-1 {
		t.Fatal("invalid rule counted")
	}
	s.Reset()
	for range 32 {
		s.Insert("IP-CIDR,198.51.100.8/32,no-resolve")
	}
	s.FinishInsert()
	if !s.Match(&C.Metadata{DstIP: netip.MustParseAddr("192.0.2.1")}, C.RuleMatchHelper{}) || s.Match(&C.Metadata{DstIP: netip.MustParseAddr("198.51.100.8")}, C.RuleMatchHelper{}) {
		t.Fatal("index ignored the parser's rewritten prefix")
	}
}

func BenchmarkClassicalIPRules(b *testing.B) {
	lines := classicalIPLines(10000)
	b.Run("build", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = loadClassical(lines, true)
		}
	})
	s := loadClassical(lines, true)
	for _, tc := range []struct{ name, address string }{
		{"first_hit", "10.0.0.1"}, {"last_hit", "10.39.15.127"},
		{"miss", "10.39.15.128"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			m := &C.Metadata{DstIP: netip.MustParseAddr(tc.address)}
			b.ReportAllocs()
			for b.Loop() {
				_ = s.Match(m, C.RuleMatchHelper{})
			}
		})
	}
}
