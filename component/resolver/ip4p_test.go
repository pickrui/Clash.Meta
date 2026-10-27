package resolver

import (
	"net/netip"
	"testing"
)

func TestLookupIP4PAddressFamilies(t *testing.T) {
	previous := GetIP4PEnable()
	t.Cleanup(func() { SetIP4PEnable(previous) })
	SetIP4PEnable(true)
	for _, test := range []struct {
		name string
		addr netip.Addr
		want netip.Addr
		port string
	}{
		{"ipv4-prefix", netip.MustParseAddr("32.1.0.0"), netip.MustParseAddr("32.1.0.0"), "443"},
		{"ip4p", netip.MustParseAddr("2001::50:c000:201"), netip.MustParseAddr("192.0.2.1"), "80"},
		{"ipv6", netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::1"), "443"},
		{"mapped-ipv4", netip.MustParseAddr("::ffff:32.1.0.0"), netip.MustParseAddr("::ffff:32.1.0.0"), "443"},
		{"invalid", netip.Addr{}, netip.Addr{}, "443"},
	} {
		t.Run(test.name, func(t *testing.T) {
			addr, port := LookupIP4P(test.addr, "443")
			if addr != test.want || port != test.port {
				t.Fatalf("LookupIP4P(%s, 443) = %s, %s; want %s, %s", test.addr, addr, port, test.want, test.port)
			}
		})
	}
	SetIP4PEnable(false)
	input := netip.MustParseAddr("2001::50:c000:201")
	if addr, port := LookupIP4P(input, "443"); addr != input || port != "443" {
		t.Fatalf("disabled conversion changed %s:443 to %s:%s", input, addr, port)
	}
}
