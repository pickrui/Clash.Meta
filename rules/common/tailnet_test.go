package common

import (
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/tailnet"
	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

type tailnetSource struct{ routes *tailnet.Routes }

func (s tailnetSource) Routes() *tailnet.Routes { return s.routes }

func TestTailnetRuleFollowsRegisteredRoutes(t *testing.T) {
	rule := NewTailnet("Home", "Home")
	peer := netip.MustParseAddr("100.64.0.7")
	require.Equal(t, C.Tailnet, rule.RuleType())
	require.Equal(t, "Home", rule.Payload())

	matched, _ := rule.Match(&C.Metadata{DstIP: peer}, C.RuleMatchHelper{})
	require.False(t, matched, "no routes before the network map arrives")

	unregister := tailnet.Register("Home", tailnetSource{tailnet.NewRoutes(
		[]string{"tail1234.ts.net"},
		[]string{"nas"},
		[]netip.Addr{peer},
		[]netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
	)})
	defer unregister()

	for _, metadata := range []*C.Metadata{
		{DstIP: peer},
		{Host: "nas"},
		{Host: "printer.tail1234.ts.net", DstIP: netip.MustParseAddr("198.18.0.9")},
		{DstIP: netip.MustParseAddr("198.51.100.7")},
	} {
		matched, adapter := rule.Match(metadata, C.RuleMatchHelper{})
		require.True(t, matched, "%+v", metadata)
		require.Equal(t, "Home", adapter)
	}
	for _, metadata := range []*C.Metadata{
		{DstIP: netip.MustParseAddr("100.64.0.8")},
		{Host: "example.com", DstIP: netip.MustParseAddr("93.184.216.34")},
		// A hostname without an address is never resolved to test the subnet.
		{Host: "nas.example"},
	} {
		matched, _ := rule.Match(metadata, C.RuleMatchHelper{})
		require.False(t, matched, "%+v", metadata)
	}
}

func TestTailnetRuleClaimsAnUnresolvedHost(t *testing.T) {
	rule := NewTailnet("Home", "Home")
	unregister := tailnet.Register("Home", tailnetSource{tailnet.NewRoutes(
		nil, nil, nil, []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
	)})
	defer unregister()

	var claims []func(netip.Addr) bool
	helper := C.RuleMatchHelper{
		ResolveIP: func() { t.Fatal("the rule resolved a host itself") },
		ClaimResolved: func(claimed C.Rule, matchAddr func(netip.Addr) bool) {
			require.Same(t, rule, claimed)
			claims = append(claims, matchAddr)
		},
	}
	matched, _ := rule.Match(&C.Metadata{Host: "nas.example"}, helper)
	require.False(t, matched)
	require.Len(t, claims, 1)
	require.True(t, claims[0](netip.MustParseAddr("198.51.100.7")))
	require.False(t, claims[0](netip.MustParseAddr("203.0.113.7")))

	matched, _ = rule.Match(&C.Metadata{Host: "nas.example", DstIP: netip.MustParseAddr("198.51.100.7")}, helper)
	require.True(t, matched, "a resolved host is judged by its address")
	require.Len(t, claims, 1)
}
