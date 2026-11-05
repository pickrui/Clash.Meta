package tailnet

import (
	"net"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/iface"
	"github.com/stretchr/testify/require"
)

func TestRoutesMatchHost(t *testing.T) {
	routes := NewRoutes(
		[]string{"Tail1234.ts.net."},
		[]string{"nas.tail1234.ts.net.", "nas", "Office-PC.corp.example"},
		nil,
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
	}, nil)
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

func TestRoutesMatchSubnetsOutsideLocalNetworks(t *testing.T) {
	restore := networkInterfaces
	networkInterfaces = func() (map[string]*iface.Interface, error) {
		return map[string]*iface.Interface{
			"lan": {Flags: net.FlagUp, Addresses: []netip.Prefix{netip.MustParsePrefix("192.168.30.0/24")}},
			"tunnel": {Flags: net.FlagUp | net.FlagPointToPoint, Addresses: []netip.Prefix{
				netip.MustParsePrefix("192.168.30.7/32"), netip.MustParsePrefix("192.168.40.0/24"),
			}},
			"down": {Addresses: []netip.Prefix{netip.MustParsePrefix("192.168.40.0/24")}},
			"loopback": {Flags: net.FlagUp | net.FlagLoopback, Addresses: []netip.Prefix{
				netip.MustParsePrefix("192.168.40.0/24"),
			}},
		}, nil
	}
	t.Cleanup(func() { networkInterfaces = restore })

	routes := NewRoutes(nil, nil, []netip.Addr{netip.MustParseAddr("192.168.30.2")}, []netip.Prefix{
		netip.MustParsePrefix("192.168.30.9/16"),
		netip.MustParsePrefix("fd12:42::/64"),
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("::/0"),
	})
	require.False(t, routes.Empty())
	for addr, want := range map[string]bool{
		"192.168.40.7":        true,  // approved subnet, remote
		"::ffff:192.168.40.7": true,  // mapped form of the same address
		"fd12:42::7":          true,  // approved IPv6 subnet
		"192.168.30.7":        false, // the attached LAN stays local
		"192.168.30.2":        true,  // an exact peer keeps its owner even there
		"192.169.0.1":         false, // outside every subnet
		"8.8.8.8":             false, // exit defaults are not subnets
		"2001:4860::8888":     false,
	} {
		require.Equal(t, want, routes.MatchAddr(netip.MustParseAddr(addr)), addr)
	}
	require.True(t, routes.Contains(netip.MustParseAddr("192.168.30.7")), "an explicit route still reaches the remote side")
	require.False(t, routes.Contains(netip.MustParseAddr("192.169.0.1")))
	require.False(t, routes.Contains(netip.MustParseAddr("8.8.8.8")))
	require.True(t, NewRoutes(nil, nil, nil, []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}).Empty())
}

type staticSource struct{ routes *Routes }

func (s staticSource) Routes() *Routes { return s.routes }

func TestRegisterKeepsNewestSource(t *testing.T) {
	older := NewRoutes(nil, []string{"older"}, nil, nil)
	newer := NewRoutes(nil, []string{"newer"}, nil, nil)
	unregisterOlder := Register("Home", staticSource{older})
	unregisterNewer := Register("Home", staticSource{newer})

	unregisterOlder()
	require.Same(t, newer, Lookup("Home"))

	unregisterNewer()
	require.Nil(t, Lookup("Home"))
}
