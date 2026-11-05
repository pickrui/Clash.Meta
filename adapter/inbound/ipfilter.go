package inbound

import (
	"net"
	"net/netip"
	"slices"
	"sync/atomic"

	C "github.com/metacubex/mihomo/constant"
)

var lanAllowedIPs atomic.Pointer[[]netip.Prefix]
var lanDisAllowedIPs atomic.Pointer[[]netip.Prefix]

func SetAllowedIPs(prefixes []netip.Prefix) {
	snapshot := slices.Clone(prefixes)
	lanAllowedIPs.Store(&snapshot)
}

func SetDisAllowedIPs(prefixes []netip.Prefix) {
	snapshot := slices.Clone(prefixes)
	lanDisAllowedIPs.Store(&snapshot)
}

func AllowedIPs() []netip.Prefix {
	if snapshot := lanAllowedIPs.Load(); snapshot != nil {
		return slices.Clone(*snapshot)
	}
	return nil
}

func DisAllowedIPs() []netip.Prefix {
	if snapshot := lanDisAllowedIPs.Load(); snapshot != nil {
		return slices.Clone(*snapshot)
	}
	return nil
}

func IsRemoteAddrDisAllowed(addr net.Addr) bool {
	m := C.Metadata{}
	if err := m.SetRemoteAddr(addr); err != nil {
		return false
	}
	ipAddr := m.AddrPort().Addr()
	if ipAddr.IsValid() {
		return isAllowed(ipAddr) && !isDisAllowed(ipAddr)
	}
	return false
}

func isAllowed(addr netip.Addr) bool {
	snapshot := lanAllowedIPs.Load()
	return snapshot != nil && prefixesContains(*snapshot, addr)
}

func isDisAllowed(addr netip.Addr) bool {
	snapshot := lanDisAllowedIPs.Load()
	return snapshot != nil && prefixesContains(*snapshot, addr)
}
