package iface

import (
	"errors"
	"fmt"
	"math/rand"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/singledo"
)

// Install an immutable in-memory snapshot so public lookup tests never enumerate
// or change host interfaces. Tests using this package-global fixture stay serial.
func installInterfaceSnapshot(t *testing.T, interfaces ...*Interface) {
	t.Helper()
	snapshot := &ifaceCache{
		ifMapByName: make(map[string]*Interface),
		ifMapByAddr: make(map[netip.Addr]*Interface),
	}
	for _, entry := range interfaces {
		snapshot.ifMapByName[entry.Name] = entry
		for _, prefix := range entry.Addresses {
			snapshot.ifMapByAddr[prefix.Addr()] = entry
			snapshot.ifTable.Insert(prefix, entry)
		}
	}
	previous := caches
	caches = singledo.NewSingle[*ifaceCache](time.Hour)
	_, _, _ = caches.Do(func() (*ifaceCache, error) { return snapshot, nil })
	t.Cleanup(func() { caches = previous })
}

func TestResolveInterfaceByAddrPrecedence(t *testing.T) {
	makeInterface := func(name string, prefixes ...string) *Interface {
		entry := &Interface{Name: name}
		for _, prefix := range prefixes {
			entry.Addresses = append(entry.Addresses, netip.MustParsePrefix(prefix))
		}
		return entry
	}
	lan := makeInterface("lan", "10.0.0.1/8", "10.1.2.1/24")
	peer := makeInterface("peer", "10.1.2.2/24")
	vpn := makeInterface("vpn", "10.1.2.129/25")
	host := makeInterface("host", "10.1.2.200/32")
	ipv6 := makeInterface("ipv6", "2001:db8::1/32")
	subnet6 := makeInterface("subnet6", "2001:db8:1234::1/48")
	host6 := makeInterface("host6", "2001:db8:1234::7/128")
	installInterfaceSnapshot(t, lan, peer, vpn, host, ipv6, subnet6, host6)
	for _, tc := range []struct {
		name, address string
		want          *Interface
		local         bool
	}{
		{"exact address wins over equal subnet", "10.1.2.1", lan, true},
		{"second exact address", "10.1.2.2", peer, true},
		{"same subnet uses latest prefix", "10.1.2.3", peer, false},
		{"more specific subnet", "10.1.2.150", vpn, false},
		{"host prefix", "10.1.2.200", host, true},
		{"backtrack to broad prefix", "10.2.3.4", lan, false},
		{"IPv6 exact address", "2001:db8::1", ipv6, true},
		{"IPv6 subnet", "2001:db8:1234::9", subnet6, false},
		{"IPv6 host", "2001:db8:1234::7", host6, true},
		{"IPv6 backtrack", "2001:db8:5678::1", ipv6, false},
		{"IPv4 miss", "192.0.2.1", nil, false},
		{"IPv6 miss", "2001:db9::1", nil, false},
		{"mapped address is not native IPv4", "::ffff:10.1.2.1", nil, false},
		{"invalid address", "", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			address, _ := netip.ParseAddr(tc.address)
			got, err := ResolveInterfaceByAddr(address)
			if got != tc.want || (tc.want == nil && !errors.Is(err, ErrIfaceNotFound)) || (tc.want != nil && err != nil) {
				t.Fatalf("lookup(%s) = %v, %v; want %v", address, got, err, tc.want)
			}
			local, err := IsLocalIp(address)
			if err != nil || local != tc.local {
				t.Fatalf("local(%s) = %v, %v", address, local, err)
			}
		})
	}
}

func TestResolveInterfaceByAddrEmptySnapshot(t *testing.T) {
	installInterfaceSnapshot(t)
	for _, address := range []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1"), {}} {
		if got, err := ResolveInterfaceByAddr(address); got != nil || !errors.Is(err, ErrIfaceNotFound) {
			t.Fatalf("empty snapshot lookup(%s) = %v, %v", address, got, err)
		}
	}
}

func TestResolveInterfaceByAddrMatchesLinearSearch(t *testing.T) {
	random := rand.New(rand.NewSource(97))
	var interfaces []*Interface
	var probes []netip.Addr
	randomAddress := func(ipv4 bool) netip.Addr {
		var raw [16]byte
		_, _ = random.Read(raw[:])
		if ipv4 {
			return netip.AddrFrom4([4]byte(raw[:4]))
		}
		return netip.AddrFrom16(raw)
	}
	// Exercise every bit boundary, including /0, /32, /128 and unmasked host bits.
	for _, ipv4 := range []bool{true, false} {
		maxBits := 128
		if ipv4 {
			maxBits = 32
		}
		for bits := 0; bits <= maxBits; bits++ {
			address := randomAddress(ipv4)
			prefix := netip.PrefixFrom(address, bits)
			entry := &Interface{Name: fmt.Sprintf("iface-%d", len(interfaces)), Addresses: []netip.Prefix{prefix}}
			interfaces = append(interfaces, entry)
			if bits%8 == 0 {
				interfaces = append(interfaces, &Interface{Name: entry.Name + "-replacement", Addresses: []netip.Prefix{prefix.Masked()}})
			}
			probes = append(probes, address, address.Next(), address.Prev(), prefix.Masked().Addr())
		}
		for i := 0; i < 512; i++ {
			probes = append(probes, randomAddress(ipv4))
		}
	}
	installInterfaceSnapshot(t, interfaces...)
	// Independent oracle: search the original entries in reverse for exact
	// addresses, then scan for the most specific containing prefix.
	expected := make([]*Interface, len(probes))
	for i, address := range probes {
		bestBits := -1
		for j := len(interfaces) - 1; j >= 0; j-- {
			entry := interfaces[j]
			prefix := entry.Addresses[0]
			if prefix.Addr() == address {
				expected[i] = entry
				break
			}
			if prefix.Contains(address) && prefix.Bits() > bestBits {
				expected[i], bestBits = entry, prefix.Bits()
			}
		}
	}
	var readers sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for i, address := range probes {
				got, err := ResolveInterfaceByAddr(address)
				if err != nil || got != expected[i] {
					t.Errorf("lookup(%s) = %v, %v; want %v", address, got, err, expected[i])
					return
				}
			}
		}()
	}
	readers.Wait()
	t.Logf("checked %d prefixes and %d probes with 8 concurrent readers", len(interfaces), len(probes))
}
