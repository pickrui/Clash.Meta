package inbound

import (
	"net"
	"net/netip"
	"sync"
	"testing"
)

func TestConcurrentIPFilterReplacement(t *testing.T) {
	allowed, denied := AllowedIPs(), DisAllowedIPs()
	t.Cleanup(func() {
		SetAllowedIPs(allowed)
		SetDisAllowedIPs(denied)
	})
	loopback := netip.MustParsePrefix("127.0.0.0/8")
	private := netip.MustParsePrefix("10.0.0.0/8")
	SetAllowedIPs([]netip.Prefix{loopback})
	SetDisAllowedIPs([]netip.Prefix{private})
	remote := net.TCPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:12345"))
	var workers sync.WaitGroup
	for i := 0; i < 4; i++ {
		workers.Go(func() {
			for j := 0; j < 1000; j++ {
				SetAllowedIPs([]netip.Prefix{loopback})
				SetDisAllowedIPs([]netip.Prefix{private})
				if !IsRemoteAddrDisAllowed(remote) {
					t.Error("replacement rejected an address allowed by both policies")
					return
				}
				_ = AllowedIPs()
				_ = DisAllowedIPs()
			}
		})
	}
	workers.Wait()
}

func TestIPFilterAllowAndDeny(t *testing.T) {
	allowed, denied := AllowedIPs(), DisAllowedIPs()
	t.Cleanup(func() {
		SetAllowedIPs(allowed)
		SetDisAllowedIPs(denied)
	})
	SetAllowedIPs([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("2001:db8::/32"),
	})
	SetDisAllowedIPs([]netip.Prefix{
		netip.MustParsePrefix("10.1.0.0/16"),
		netip.MustParsePrefix("2001:db8:1::/48"),
	})
	for _, tc := range []struct {
		address string
		allowed bool
	}{
		{"10.2.0.1:12345", true},
		{"10.1.0.1:12345", false},
		{"127.0.0.1:12345", false},
		{"[::ffff:10.2.0.1]:12345", true},
		{"[2001:db8:2::1]:12345", true},
		{"[2001:db8:1::1]:12345", false},
	} {
		t.Run(tc.address, func(t *testing.T) {
			remote := net.TCPAddrFromAddrPort(netip.MustParseAddrPort(tc.address))
			if got := IsRemoteAddrDisAllowed(remote); got != tc.allowed {
				t.Errorf("allowed = %v, want %v", got, tc.allowed)
			}
		})
	}
	SetAllowedIPs(nil)
	SetDisAllowedIPs(nil)
	if IsRemoteAddrDisAllowed(net.TCPAddrFromAddrPort(netip.MustParseAddrPort("10.2.0.1:12345"))) {
		t.Fatal("empty allow list must reject the address")
	}
}
