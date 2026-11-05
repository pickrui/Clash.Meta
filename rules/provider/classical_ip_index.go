package provider

import (
	"slices"
	"sort"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/rules/common"

	"go4.org/netipx"
)

const minClassicalIPRun = 16

type classicalIPRun struct {
	ranges []netipx.IPRange
	source bool
}

func classicalIPRule(rule classicalMatcher) *common.IPCIDR {
	r, ok := rule.(*common.IPCIDR)
	if !ok || r == nil || r.ResolvesIP() {
		return nil
	}
	return r
}

// Resolving rules remain separate: each callback may change later metadata.
func newClassicalIPRun(rules []classicalMatcher, source bool) *classicalIPRun {
	ranges := make([]netipx.IPRange, len(rules))
	for i, rule := range rules {
		ranges[i] = netipx.RangeOfPrefix(rule.(*common.IPCIDR).Prefix())
	}
	slices.SortFunc(ranges, func(a, b netipx.IPRange) int {
		return a.From().Compare(b.From())
	})
	kept := 0
	for _, next := range ranges {
		if kept == 0 {
			ranges[kept] = next
			kept++
			continue
		}
		previous := ranges[kept-1]
		if previous.To().Less(next.From()) && previous.To().Next() != next.From() {
			ranges[kept] = next
			kept++
		} else if previous.To().Less(next.To()) {
			ranges[kept-1] = netipx.IPRangeFrom(previous.From(), next.To())
		}
	}
	ranges = ranges[:kept]
	if kept < cap(ranges)/2 {
		ranges = slices.Clone(ranges)
	}
	return &classicalIPRun{ranges: ranges, source: source}
}

func (r *classicalIPRun) Match(metadata *C.Metadata, _ C.RuleMatchHelper) (bool, string) {
	ip := metadata.DstIP
	if r.source {
		ip = metadata.SrcIP
	}
	if !ip.IsValid() {
		return false, ""
	}
	ip = ip.WithZone("")
	index := sort.Search(len(r.ranges), func(i int) bool {
		return ip.Less(r.ranges[i].From())
	}) - 1
	return index >= 0 && !r.ranges[index].To().Less(ip), ""
}
