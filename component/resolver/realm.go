package resolver

import (
	"context"
	"net/netip"
)

// LookupIPForHysteria2Realm resolves peer addresses using the proxy server DNS policy.
func LookupIPForHysteria2Realm(ctx context.Context, host string, ipv4, ipv6 bool) ([]netip.Addr, error) {
	if ipv4 && !ipv6 {
		return LookupIPv4WithResolver(ctx, host, ProxyServerHostResolver)
	} else if ipv6 && !ipv4 {
		return LookupIPv6WithResolver(ctx, host, ProxyServerHostResolver)
	}
	return LookupIPWithResolver(ctx, host, ProxyServerHostResolver)
}
