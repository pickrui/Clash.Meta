//go:build !no_zerotier

package outbound

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
	ZT "github.com/metacubex/zerotier-go"
	ZTIP "github.com/metacubex/zerotier-go/iplink"
	"github.com/stretchr/testify/require"
)

func zeroTierDNSFixture(t testing.TB) *ZeroTier {
	t.Helper()
	node, err := NewZeroTier(ZeroTierOption{
		Name: "dns-fixture", Network: "8056c2e21c000001", RemoteDnsResolve: true,
		IPStack: IPStackOption{Mode: ipStackMips},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = node.Close() })
	return node
}

func TestZeroTierDNSConfigurationStaysLazy(t *testing.T) {
	node := zeroTierDNSFixture(t)
	config := ZT.NetworkConfigData{
		Assigned: []netip.Prefix{netip.MustParsePrefix("2001:db8::2/64")},
		DNSServers: []netip.AddrPort{
			netip.MustParseAddrPort("192.0.2.53:0"), netip.MustParseAddrPort("[2001:db8::53]:5353"),
		},
	}
	owner, err := node.resolverForNetworkConfig(config)
	require.NoError(t, err)
	t.Cleanup(owner.close)
	require.Nil(t, owner.current)
	require.True(t, owner.ipv6)
	require.Equal(t, "192.0.2.53:53", owner.servers[0].Addr)
	require.Equal(t, "[2001:db8::53]:5353", owner.servers[1].Addr)
	require.Same(t, node, owner.servers[0].ProxyAdapter)
	node.dns = []dns.NameServer{{Addr: "198.51.100.53:53"}}
	configured, err := node.resolverForNetworkConfig(config)
	require.NoError(t, err)
	t.Cleanup(configured.close)
	require.Equal(t, "198.51.100.53:53", configured.servers[0].Addr)
	require.Nil(t, node.dns[0].ProxyAdapter)
	node.option.RemoteDnsResolve = false
	disabled, err := node.resolverForNetworkConfig(config)
	require.NoError(t, err)
	require.Nil(t, disabled)
}

func TestZeroTierDNSReuseFollowsEffectiveServers(t *testing.T) {
	node := zeroTierDNSFixture(t)
	base := ZT.NetworkConfigData{
		Timestamp:  1,
		Assigned:   []netip.Prefix{netip.MustParsePrefix("192.0.2.2/24")},
		DNSServers: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.53:53")},
	}
	refreshed, moved, ipv6 := base, base, base
	refreshed.Timestamp++
	moved.DNSServers = []netip.AddrPort{netip.MustParseAddrPort("198.51.100.53:53")}
	ipv6.Assigned = append(append([]netip.Prefix(nil), base.Assigned...), netip.MustParsePrefix("2001:db8::2/64"))
	require.True(t, node.sameDNSInputs(base, refreshed))
	require.False(t, node.sameDNSInputs(base, moved))
	require.False(t, node.sameDNSInputs(base, ipv6))
	node.dns = []dns.NameServer{{Addr: "203.0.113.53:53"}}
	require.True(t, node.sameDNSInputs(base, moved))
	require.False(t, node.sameDNSInputs(base, ipv6))
}

func TestZeroTierSessionRetiresPrivateDNS(t *testing.T) {
	for _, event := range []string{"close", "network failure", "stack failure"} {
		t.Run(event, func(t *testing.T) {
			node := zeroTierDNSFixture(t)
			owner, _, assertRetired := blockedSessionDNS(t)
			device := &sessionDNSStack{closed: make(chan struct{})}
			node.resolver, node.tunDevice = owner, device
			start := time.Now()
			switch event {
			case "close":
				require.NoError(t, node.Close())
				err := node.ResolveUDP(context.Background(), &C.Metadata{Host: "late.test"})
				require.ErrorIs(t, err, context.Canceled)
			case "network failure":
				require.True(t, node.invalidateNetwork(nil, errors.New("network removed"), "", false))
			case "stack failure":
				require.True(t, node.invalidateDevice(device, errors.New("stack stopped")))
			}
			assertRetired()
			require.Nil(t, node.resolver)
			require.Nil(t, owner.current)
			_, err := owner.get(context.Background())
			require.ErrorIs(t, err, net.ErrClosed)
			select {
			case <-device.closed:
			case <-time.After(time.Second):
				t.Fatal("retired stack did not close")
			}
			t.Logf("retired 32 DNS queries in %s", time.Since(start))
		})
	}
}

func TestZeroTierCloseCancelsDNSBeforeWaitingForOperation(t *testing.T) {
	node := zeroTierDNSFixture(t)
	owner, _, assertRetired := blockedSessionDNS(t)
	node.resolver = owner
	node.operationMu.Lock()
	closed := make(chan error, 1)
	go func() { closed <- node.Close() }()
	defer func() {
		node.operationMu.Unlock()
		require.NoError(t, <-closed)
	}()
	require.Eventually(t, func() bool {
		owner.mu.Lock()
		defer owner.mu.Unlock()
		return owner.closed
	}, time.Second, time.Millisecond)
	assertRetired()
}

func TestZeroTierPrivateDNSErrorPropagation(t *testing.T) {
	node := zeroTierDNSFixture(t)
	node.runtime = &zeroTierRuntime{}
	t.Cleanup(func() { node.runtime = nil })
	node.tunDevice = &sessionDNSStack{closed: make(chan struct{})}
	node.resolver = &nodeDNS{servers: []dns.NameServer{{Net: "rcode", Addr: "success"}}}
	metadata := &C.Metadata{Host: "missing.test", DstPort: 443}
	_, err := node.DialContext(context.Background(), metadata)
	require.ErrorIs(t, err, resolver.ErrIPNotFound)
	require.ErrorIs(t, node.ResolveUDP(context.Background(), metadata), resolver.ErrIPNotFound)
}

type zeroTierDNSLinkSender struct {
	onSubscribe func()
}

func (*zeroTierDNSLinkSender) Address() ZT.Address { return ZT.Address(1) }
func (*zeroTierDNSLinkSender) SendFrame(uint64, ZT.MAC, uint16, []byte) error {
	return errors.New("physical network disabled in fixture")
}
func (s *zeroTierDNSLinkSender) SubscribeMulticast(uint64, ZT.MulticastGroup) error {
	if fn := s.onSubscribe; fn != nil {
		s.onSubscribe = nil
		fn()
	}
	return nil
}
func (*zeroTierDNSLinkSender) UnsubscribeMulticast(uint64, ZT.MulticastGroup) error { return nil }

func TestZeroTierDNSReplacementAndRejectedUpdates(t *testing.T) {
	node := zeroTierDNSFixture(t)
	sender := &zeroTierDNSLinkSender{}
	link, err := ZTIP.New(node.networkID, sender)
	require.NoError(t, err)
	node.runtime = &zeroTierRuntime{ipLink: link}
	t.Cleanup(func() { node.runtime = nil })
	config := ZT.NetworkConfigData{
		NetworkID: node.networkID, MTU: 1280,
		Assigned:   []netip.Prefix{netip.MustParsePrefix("192.0.2.2/24")},
		DNSServers: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.53:53")},
	}
	node.config, node.latestConfig, node.haveLatestConfig = config, config, true
	node.tunDevice = &sessionDNSStack{closed: make(chan struct{})}
	owner, inFlight, assertRetired := blockedSessionDNS(t)
	node.resolver = owner
	refreshed := config
	refreshed.Timestamp++
	node.latestConfig = refreshed
	require.NoError(t, node.applyNetworkConfig(refreshed, node.configGeneration))
	require.Same(t, owner, node.resolver)
	require.False(t, owner.closed)
	reused, err := owner.get(context.Background())
	require.NoError(t, err)
	require.Same(t, inFlight, reused)
	config = refreshed
	config.DNSServers = []netip.AddrPort{netip.MustParseAddrPort("203.0.113.53:53")}
	node.latestConfig = config
	require.NoError(t, node.applyNetworkConfig(config, node.configGeneration))
	assertRetired()
	current := node.resolver
	require.NotSame(t, owner, current)
	require.Nil(t, current.current)
	_, err = current.get(context.Background())
	require.NoError(t, err)
	for _, failure := range []string{"wrong network", "stale before apply", "stale after link update"} {
		t.Run(failure, func(t *testing.T) {
			next := config
			next.DNSServers = []netip.AddrPort{netip.MustParseAddrPort("198.51.100.53:53")}
			generation := node.configGeneration
			switch failure {
			case "wrong network":
				next.NetworkID++
			case "stale before apply":
				generation--
			case "stale after link update":
				next.Assigned = append(append([]netip.Prefix(nil), config.Assigned...), netip.MustParsePrefix("2001:db8::2/64"))
				sender.onSubscribe = func() {
					node.stateMu.Lock()
					node.configGeneration++
					node.stateMu.Unlock()
				}
			}
			node.latestConfig = next
			require.Error(t, node.applyNetworkConfig(next, generation))
			require.Same(t, current, node.resolver)
			require.False(t, current.closed)
			require.Equal(t, config, node.config)
		})
	}
	currentDevice := node.tunDevice
	staleDevice := &sessionDNSStack{closed: make(chan struct{})}
	require.False(t, node.invalidateDevice(staleDevice, errors.New("old stack")))
	require.False(t, node.invalidateNetwork(&zeroTierRuntime{}, errors.New("old runtime"), "", false))
	require.Same(t, current, node.resolver)
	require.True(t, node.invalidateDevice(currentDevice, errors.New("current stack")))
	require.True(t, current.closed)
}
