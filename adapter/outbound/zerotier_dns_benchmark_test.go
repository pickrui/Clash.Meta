//go:build !no_zerotier

package outbound

import (
	"net/netip"
	"testing"

	ZT "github.com/metacubex/zerotier-go"
)

func BenchmarkZeroTierPrivateDNSConfig(b *testing.B) {
	node, err := NewZeroTier(ZeroTierOption{Name: "dns-config", Network: "8056c2e21c000001", RemoteDnsResolve: true})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = node.Close() })
	config := ZT.NetworkConfigData{
		Assigned:   []netip.Prefix{netip.MustParsePrefix("192.0.2.2/24")},
		DNSServers: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.53:53")},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		owner, err := node.resolverForNetworkConfig(config)
		if err != nil {
			b.Fatal(err)
		}
		node.resolver = owner
	}
}
