package tailnet

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRoutesMatchHost(t *testing.T) {
	routes := NewRoutes(
		[]string{"Tail1234.ts.net.", "ts.net"},
		[]string{"nas.tail1234.ts.net.", "nas", "Office-PC.corp.example"},
		nil,
	)
	for host, want := range map[string]bool{
		"nas.tail1234.ts.net":     true,
		"NAS.tail1234.ts.net.":    true,
		"printer.tail1234.ts.net": true,
		"tail1234.ts.net":         true,
		"nas":                     true,
		"office-pc.corp.example":  true,
		"other.ts.net":            false,
		"ts.net":                  false,
		"nas.example":             false,
		"xtail1234.ts.net":        false,
		"":                        false,
	} {
		require.Equal(t, want, routes.MatchHost(host), host)
	}
}

func TestRoutesMatchAddr(t *testing.T) {
	routes := NewRoutes(nil, nil, []netip.Addr{
		netip.MustParseAddr("100.101.102.103"),
		netip.MustParseAddr("fd7a:115c:a1e0::1"),
	})
	require.True(t, routes.MatchAddr(netip.MustParseAddr("100.101.102.103")))
	require.True(t, routes.MatchAddr(netip.MustParseAddr("::ffff:100.101.102.103")))
	require.True(t, routes.MatchAddr(netip.MustParseAddr("fd7a:115c:a1e0::1")))
	require.False(t, routes.MatchAddr(netip.MustParseAddr("100.101.102.104")))
	require.False(t, routes.MatchAddr(netip.Addr{}))

	var empty *Routes
	require.True(t, empty.Empty())
	require.False(t, empty.MatchAddr(netip.MustParseAddr("100.101.102.103")))
	require.False(t, empty.MatchHost("nas"))
}

type staticSource struct{ routes *Routes }

func (s staticSource) Routes() *Routes { return s.routes }

func TestRegisterKeepsNewestSource(t *testing.T) {
	older := NewRoutes(nil, []string{"older"}, nil)
	newer := NewRoutes(nil, []string{"newer"}, nil)
	unregisterOlder := Register("Home", staticSource{older})
	unregisterNewer := Register("Home", staticSource{newer})

	unregisterOlder()
	require.Same(t, newer, Lookup("Home"))

	unregisterNewer()
	require.Nil(t, Lookup("Home"))
}
