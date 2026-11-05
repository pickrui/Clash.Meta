package common

import (
	"fmt"
	"net/netip"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestIPSuffixAllWidths(t *testing.T) {
	for _, text := range []string{"192.0.2.165", "2001:db8:1234:5678:9abc:def0:1234:56a5"} {
		ip := netip.MustParseAddr(text)
		for bits := 0; bits <= ip.BitLen(); bits++ {
			for _, source := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%d/source=%t", text, bits, source), func(t *testing.T) {
					rule, err := NewIPSuffix(fmt.Sprintf("%s/%d", text, bits), "PROXY", source, true)
					if err != nil {
						t.Fatal(err)
					}
					assertMatch := func(candidate netip.Addr, want bool) {
						t.Helper()
						metadata := &C.Metadata{DstIP: candidate}
						if source {
							metadata = &C.Metadata{SrcIP: candidate}
						}
						got, adapter := rule.Match(metadata, C.RuleMatchHelper{})
						if got != want || (got && adapter != "PROXY") {
							t.Fatalf("match %s: got %t/%s, want %t", candidate, got, adapter, want)
						}
					}
					assertMatch(ip, true)
					assertMatch(netip.Addr{}, false)
					data := ip.AsSlice()
					data[len(data)-1] ^= 1
					candidate, _ := netip.AddrFromSlice(data)
					assertMatch(candidate, bits == 0)
					if bits < ip.BitLen() {
						data = ip.AsSlice()
						data[len(data)-1-bits/8] ^= byte(1 << (bits % 8))
						candidate, _ = netip.AddrFromSlice(data)
						assertMatch(candidate, true)
					}
				})
			}
		}
	}
}
