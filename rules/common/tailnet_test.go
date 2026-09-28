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
	)})
	defer unregister()

	for _, metadata := range []*C.Metadata{
		{DstIP: peer},
		{Host: "nas"},
		{Host: "printer.tail1234.ts.net", DstIP: netip.MustParseAddr("198.18.0.9")},
	} {
		matched, adapter := rule.Match(metadata, C.RuleMatchHelper{})
		require.True(t, matched, "%+v", metadata)
		require.Equal(t, "Home", adapter)
	}
	for _, metadata := range []*C.Metadata{
		{DstIP: netip.MustParseAddr("100.64.0.8")},
		{Host: "example.com", DstIP: netip.MustParseAddr("93.184.216.34")},
	} {
		matched, _ := rule.Match(metadata, C.RuleMatchHelper{})
		require.False(t, matched, "%+v", metadata)
	}
}
