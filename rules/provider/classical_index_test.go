package provider_test

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/rules"
	"github.com/metacubex/mihomo/rules/common"
	RP "github.com/metacubex/mihomo/rules/provider"
)

type classicalHostRewrite struct{ C.Rule }

func (r *classicalHostRewrite) Match(metadata *C.Metadata, _ C.RuleMatchHelper) (bool, string) {
	metadata.SniffHost = "changed.test"
	return false, ""
}

type classicalMatcher interface {
	Match(*C.Metadata, C.RuleMatchHelper) bool
	Count() int
}

func classicalLines(n int) []string {
	lines := make([]string, n)
	for i := range lines {
		kind := "DOMAIN"
		if i%2 == 0 {
			kind = "DOMAIN-SUFFIX"
		}
		lines[i] = fmt.Sprintf("%s,host%d.example.test", kind, i)
	}
	return lines
}

func loadClassical(lines []string, finish bool) classicalMatcher {
	s := RP.NewClassicalStrategy(rules.ParseRule)
	for _, line := range lines {
		s.Insert(line)
	}
	if finish {
		s.FinishInsert()
	}
	return s
}

func compareClassical(t *testing.T, reference, indexed classicalMatcher, input C.Metadata) {
	t.Helper()
	if indexed.Count() != reference.Count() {
		t.Fatalf("rule count = %d, want %d", indexed.Count(), reference.Count())
	}
	match := func(s classicalMatcher) (bool, C.Metadata, []string) {
		m := input
		var trace []string
		helper := C.RuleMatchHelper{
			ResolveIP: func() {
				trace = append(trace, "resolve")
				if !m.DstIP.IsValid() {
					m.DstIP = netip.MustParseAddr("192.0.2.7")
				}
			},
			FindProcess: func() { trace = append(trace, "process") },
		}
		return s.Match(&m, helper), m, trace
	}
	want, wantMetadata, wantTrace := match(reference)
	got, gotMetadata, gotTrace := match(indexed)
	if got != want || !slices.Equal(gotTrace, wantTrace) || gotMetadata.DstIP != wantMetadata.DstIP {
		t.Fatalf("%+v: match %v/%v, trace %v/%v, address %v/%v", input, got, want, gotTrace, wantTrace, gotMetadata.DstIP, wantMetadata.DstIP)
	}
}

func TestClassicalIndexMatchesLinearScan(t *testing.T) {
	edges := []string{
		"DOMAIN,Google.COM", "DOMAIN-SUFFIX,EXAMPLE.COM", "DOMAIN-SUFFIX,.example",
		"DOMAIN-SUFFIX,中文", "DOMAIN,中文.example", "DOMAIN,a..b", "DOMAIN,*.literal",
		"DOMAIN-SUFFIX,io", "DOMAIN-SUFFIX,tail.", "DOMAIN-SUFFIX,example.com",
	}
	probes := []string{"", "nomatch.test", "google.com", "Google.COM", "example.com", "www.example.com", "xexample.com", ".example", "a..example", "中文", "a.中文", "中文.example", "a..b", "*.literal", "a.literal", "IO", "a.io", "tail.", "www.tail.", strings.Repeat("a.", 4096) + "example.com", strings.Repeat("a.", 4096) + "missing.test"}
	otherRules := []string{
		"IP-CIDR,198.51.100.0/24", "IP-CIDR,192.0.2.0/24,no-resolve", "SRC-IP-CIDR,10.0.0.0/8",
		"PROCESS-NAME,editor", "DST-PORT,443", "DOMAIN-KEYWORD,tracker", "DOMAIN-REGEX,^regex[0-9]+$",
		"AND,((DOMAIN-SUFFIX,logic.test),(PROCESS-NAME,editor))", "OR,((DOMAIN,alternative.test),(DST-PORT,8443))",
		"NOT,((DOMAIN-SUFFIX,example.test))",
	}
	for seed := uint64(1); seed <= 12; seed++ {
		rng := rand.New(rand.NewPCG(seed, 1))
		var lines []string
		for range 6 {
			lines = append(lines, classicalLines(32+rng.IntN(64))...)
			lines = append(lines, edges...)
			lines = append(lines, otherRules[rng.IntN(len(otherRules))])
		}
		reference, indexed := loadClassical(lines, false), loadClassical(lines, true)
		for trial := range 300 {
			host := probes[rng.IntN(len(probes))]
			if trial%3 == 0 {
				host = fmt.Sprintf("host%d.example.test", rng.IntN(100))
			}
			m := C.Metadata{Host: host, DstPort: uint16(440 + rng.IntN(5)), Process: "editor", SrcIP: netip.MustParseAddr("10.0.0.1")}
			if trial%4 == 0 {
				m.SniffHost = host
				m.Host = "different.test"
			}
			if trial%5 == 0 {
				m.DstIP = netip.MustParseAddr("2001:db8::1")
			}
			compareClassical(t, reference, indexed, m)
		}
	}
}

func TestClassicalIndexKeepsSideEffectBoundaries(t *testing.T) {
	prefix := classicalLines(64)
	for _, middle := range []string{
		"IP-CIDR,198.51.100.0/24", "PROCESS-NAME,other", "AND,((DOMAIN-SUFFIX,test),(PROCESS-NAME,other))",
	} {
		for _, host := range []string{"host0.example.test", "missing.test", "last.test"} {
			lines := append(slices.Clone(prefix), middle)
			lines = append(lines, classicalLines(64)...)
			lines = append(lines, "DOMAIN,last.test")
			compareClassical(t, loadClassical(lines, false), loadClassical(lines, true), C.Metadata{Host: host})
		}
	}
}

func TestClassicalIndexLifecycle(t *testing.T) {
	probes := []C.Metadata{
		{}, {Host: "one.test"}, {Host: "sub.one.test"}, {Host: "one.test."}, {Host: "notone.test"},
		{DstIP: netip.MustParseAddr("192.0.2.1")}, {DstIP: netip.MustParseAddr("198.51.100.1")},
	}
	for _, tc := range []struct {
		line, late, fresh string
		lateHit, freshHit C.Metadata
	}{
		{"DOMAIN,one.test", "DOMAIN,late.test", "DOMAIN,fresh.test", C.Metadata{Host: "late.test"}, C.Metadata{Host: "fresh.test"}},
		{"DOMAIN-SUFFIX,one.test", "DOMAIN-SUFFIX,late.test", "DOMAIN,fresh.test", C.Metadata{Host: "a.late.test"}, C.Metadata{Host: "fresh.test"}},
		{"IP-CIDR,192.0.2.0/24,no-resolve", "SRC-IP-CIDR,198.51.100.0/24", "IP-CIDR,203.0.113.0/24,no-resolve",
			C.Metadata{SrcIP: netip.MustParseAddr("198.51.100.1")}, C.Metadata{DstIP: netip.MustParseAddr("203.0.113.1")}},
	} {
		for _, count := range []int{0, 1, 15, 16, 17, 64, 4096} {
			lines := slices.Repeat([]string{tc.line}, count)
			s := RP.NewClassicalStrategy(rules.ParseRule)
			for _, line := range lines {
				s.Insert(line)
			}
			s.FinishInsert()
			s.FinishInsert()
			reference := loadClassical(lines, false)
			for _, probe := range probes {
				compareClassical(t, reference, s, probe)
			}
			matches := func(m C.Metadata) bool { return s.Match(&m, C.RuleMatchHelper{}) }
			for range 16 {
				s.Insert(tc.late)
			}
			if !matches(tc.lateHit) {
				t.Fatalf("%s x%d: late insertion was lost", tc.line, count)
			}
			s.FinishInsert()
			if s.Count() != count+16 || !matches(tc.lateHit) {
				t.Fatalf("%s x%d: finishing again lost the appended run", tc.line, count)
			}
			s.Reset()
			s.Insert(tc.fresh)
			s.FinishInsert()
			if s.Count() != 1 || !matches(tc.freshHit) || matches(tc.lateHit) || slices.ContainsFunc(probes, matches) {
				t.Fatalf("%s x%d: reset retained an old index", tc.line, count)
			}
		}
	}
}

func TestClassicalIndexRespectsParser(t *testing.T) {
	calls := 0
	parse := func(tp, payload, target string, params []string, subRules map[string][]C.Rule) (C.Rule, error) {
		calls++
		if strings.HasPrefix(payload, "reject") {
			return nil, fmt.Errorf("fixture rejection")
		}
		if payload == "redirect.test" {
			return common.NewDomain("actual.test", target), nil
		}
		return rules.ParseRule(tp, payload, target, params, subRules)
	}
	s := RP.NewClassicalStrategy(parse)
	lines := append(classicalLines(64), "DOMAIN,reject.test", "DOMAIN,redirect.test")
	for _, line := range lines {
		s.Insert(line)
	}
	s.FinishInsert()
	if calls != len(lines) || s.Count() != len(lines)-1 {
		t.Fatalf("parser calls=%d count=%d", calls, s.Count())
	}
	for host, want := range map[string]bool{"actual.test": true, "redirect.test": false, "reject.test": false} {
		if got := s.Match(&C.Metadata{Host: host}, C.RuleMatchHelper{}); got != want {
			t.Fatalf("custom parser: %s = %v, want %v", host, got, want)
		}
	}
}

func TestClassicalIndexHonorsMetadataChanges(t *testing.T) {
	parse := func(tp, payload, target string, params []string, subRules map[string][]C.Rule) (C.Rule, error) {
		if payload == "rewrite.test" {
			return &classicalHostRewrite{Rule: common.NewDomain(payload, target)}, nil
		}
		return rules.ParseRule(tp, payload, target, params, subRules)
	}
	s := RP.NewClassicalStrategy(parse)
	lines := append(classicalLines(64), "DOMAIN,rewrite.test")
	lines = append(lines, classicalLines(64)...)
	lines = append(lines, "DOMAIN,changed.test")
	for _, line := range lines {
		s.Insert(line)
	}
	s.FinishInsert()
	metadata := &C.Metadata{Host: "unmatched.test"}
	if !s.Match(metadata, C.RuleMatchHelper{}) || metadata.SniffHost != "changed.test" {
		t.Fatal("a custom rule was indexed or its metadata change was ignored")
	}
}

func measureRetained(load func() classicalMatcher) (classicalMatcher, int64, int64) {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	s := load()
	runtime.GC()
	runtime.ReadMemStats(&after)
	return s, int64(after.HeapAlloc) - int64(before.HeapAlloc), int64(after.HeapObjects) - int64(before.HeapObjects)
}

func TestClassicalIndexRetainedStorage(t *testing.T) {
	const count = 20000
	for _, tc := range []struct {
		name          string
		lines         func() []string
		budgetPercent int64
	}{
		{"domain", func() []string { return classicalLines(count) }, 50},
		{"disjoint IP", func() []string { return classicalIPLines(count) }, 75},
		{"overlapping IP", func() []string {
			lines := classicalIPLines(count)
			lines[count-1] = "IP-CIDR,10.0.0.0/8,no-resolve"
			return lines
		}, 10},
	} {
		linear, linearBytes, linearObjects := measureRetained(func() classicalMatcher { return loadClassical(tc.lines(), false) })
		indexed, indexedBytes, indexedObjects := measureRetained(func() classicalMatcher { return loadClassical(tc.lines(), true) })
		t.Logf("%d %s rules: linear %d live bytes / %d objects; indexed %d live bytes / %d objects", count, tc.name, linearBytes, linearObjects, indexedBytes, indexedObjects)
		if indexedBytes*100 > linearBytes*tc.budgetPercent || indexedObjects > linearObjects/4 {
			t.Errorf("%s index retained per-rule objects or oversized storage", tc.name)
		}
		runtime.KeepAlive(linear)
		runtime.KeepAlive(indexed)
	}
}

func BenchmarkClassicalDomainRules(b *testing.B) {
	lines := classicalLines(10000)
	b.Run("build", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = loadClassical(lines, true)
		}
	})
	s := loadClassical(lines, true)
	for _, tc := range []struct{ name, host string }{
		{"first_hit", "host0.example.test"}, {"last_hit", "host9999.example.test"},
		{"suffix_hit", "www.host9998.example.test"}, {"miss", "unlisted.example.test"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			m := &C.Metadata{Host: tc.host}
			b.ReportAllocs()
			for b.Loop() {
				_ = s.Match(m, C.RuleMatchHelper{})
			}
		})
	}
}
