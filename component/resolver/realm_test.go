package resolver

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"sync"
	"testing"
)

type realmTestResolver struct {
	Resolver
	queried string
	err     error
}

func (r *realmTestResolver) Invalid() bool { return true }
func (r *realmTestResolver) LookupIPv4(context.Context, string) ([]netip.Addr, error) {
	r.queried = "A"
	return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, r.err
}
func (r *realmTestResolver) LookupIPv6(context.Context, string) ([]netip.Addr, error) {
	r.queried = "AAAA"
	return []netip.Addr{netip.MustParseAddr("2001:db8::1")}, r.err
}
func (r *realmTestResolver) LookupIP(context.Context, string) ([]netip.Addr, error) {
	r.queried = "both"
	return []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}, r.err
}
func TestRealmResolvesRequestedAddressFamilies(t *testing.T) {
	previous, disabled := ProxyServerHostResolver, DisableIPv6.Load()
	t.Cleanup(func() { ProxyServerHostResolver = previous; DisableIPv6.Store(disabled) })
	fake := &realmTestResolver{}
	ProxyServerHostResolver = fake
	DisableIPv6.Store(false)
	for _, tc := range []struct {
		name   string
		v4, v6 bool
		query  string
		ips    []netip.Addr
	}{
		{"IPv4", true, false, "A", []netip.Addr{netip.MustParseAddr("192.0.2.1")}},
		{"IPv6", false, true, "AAAA", []netip.Addr{netip.MustParseAddr("2001:db8::1")}},
		{"dual", true, true, "both", []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}},
		{"unspecified", false, false, "both", []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ips, err := LookupIPForHysteria2Realm(context.Background(), "realm-resolver.invalid", tc.v4, tc.v6)
			if err != nil || fake.queried != tc.query || !reflect.DeepEqual(ips, tc.ips) {
				t.Fatalf("got %v via %s, err=%v; want %v via %s", ips, fake.queried, err, tc.ips, tc.query)
			}
		})
	}
	DisableIPv6.Store(true)
	fake.queried = ""
	if _, err := LookupIPForHysteria2Realm(context.Background(), "realm-resolver.invalid", false, true); !errors.Is(err, ErrIPv6Disabled) || fake.queried != "" {
		t.Errorf("disabled IPv6 queried %s: %v", fake.queried, err)
	}
	DisableIPv6.Store(false)
	fake.err = errors.New("resolver failed")
	if _, err := LookupIPForHysteria2Realm(context.Background(), "realm-resolver.invalid", false, true); !errors.Is(err, fake.err) {
		t.Fatalf("lost resolver error: %v", err)
	}
}

func TestIPv6SwitchDuringLookups(t *testing.T) {
	previous := DisableIPv6.Load()
	t.Cleanup(func() { DisableIPv6.Store(previous) })
	start := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		<-start
		for range 1000 {
			ips, err := LookupIPv6WithResolver(context.Background(), "2001:db8::1", nil)
			if !errors.Is(err, ErrIPv6Disabled) && (err != nil || len(ips) != 1 || ips[0].String() != "2001:db8::1") {
				t.Errorf("unexpected IPv6 lookup result: %v, %v", ips, err)
				return
			}
			ips, err = LookupIPWithResolver(context.Background(), "192.0.2.1", nil)
			if err != nil || len(ips) != 1 || ips[0].String() != "192.0.2.1" {
				t.Errorf("IPv6 setting changed IPv4 lookup: %v, %v", ips, err)
				return
			}
		}
	}()
	close(start)
	for i := range 1000 {
		DisableIPv6.Store(i%2 == 0)
	}
	workers.Wait()
}
