package inbound

import (
	"net"
	"net/netip"
	"slices"
	"sync/atomic"

	C "github.com/metacubex/mihomo/constant"
)

var skipAuthPrefixes atomic.Pointer[[]netip.Prefix]

func SetSkipAuthPrefixes(prefixes []netip.Prefix) {
	snapshot := slices.Clone(prefixes)
	skipAuthPrefixes.Store(&snapshot)
}

func SkipAuthPrefixes() []netip.Prefix {
	if snapshot := skipAuthPrefixes.Load(); snapshot != nil {
		return slices.Clone(*snapshot)
	}
	return nil
}

func SkipAuthRemoteAddr(addr net.Addr) bool {
	m := C.Metadata{}
	if err := m.SetRemoteAddr(addr); err != nil {
		return false
	}
	return skipAuth(m.AddrPort().Addr())
}

func SkipAuthRemoteAddress(addr string) bool {
	m := C.Metadata{}
	if err := m.SetRemoteAddress(addr); err != nil {
		return false
	}
	return skipAuth(m.AddrPort().Addr())
}

func skipAuth(addr netip.Addr) bool {
	snapshot := skipAuthPrefixes.Load()
	if snapshot == nil {
		return false
	}
	return prefixesContains(*snapshot, addr)
}
