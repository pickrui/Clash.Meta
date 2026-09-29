// Package tailnet publishes the destinations a Tailscale outbound can reach, so
// a TAILNET rule follows the outbound's network map without a config reload.
package tailnet

import (
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/metacubex/mihomo/component/iface"
)

// Routes is an immutable snapshot of one tailnet's known peers and the subnet
// routes it has approved.
type Routes struct {
	suffixes []string
	names    map[string]struct{}
	addrs    map[netip.Addr]struct{}
	subnets  []netip.Prefix
}

var networkInterfaces = iface.Interfaces

func isLocalNetwork(addr netip.Addr) bool {
	interfaces, err := networkInterfaces()
	if err != nil {
		return false
	}
	// A more specific tunnel prefix must not hide an overlapping attached LAN.
	for _, attached := range interfaces {
		if attached.Flags&net.FlagUp == 0 || attached.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 {
			continue
		}
		for _, prefix := range attached.Addresses {
			if prefix.Contains(addr) {
				return true
			}
		}
	}
	return false
}

func NewRoutes(suffixes []string, names []string, addrs []netip.Addr, subnets []netip.Prefix) *Routes {
	routes := &Routes{
		names: make(map[string]struct{}, len(names)),
		addrs: make(map[netip.Addr]struct{}, len(addrs)),
	}
	for _, suffix := range suffixes {
		if suffix = NormalizeName(suffix); suffix != "" {
			routes.suffixes = append(routes.suffixes, suffix)
		}
	}
	for _, name := range names {
		if name = NormalizeName(name); name != "" {
			routes.names[name] = struct{}{}
		}
	}
	for _, addr := range addrs {
		if addr.IsValid() {
			routes.addrs[addr.Unmap()] = struct{}{}
		}
	}
	for _, subnet := range subnets {
		// An exit default is not a subnet: exit traffic needs an explicit rule.
		if subnet.IsValid() && subnet.Bits() > 0 {
			routes.subnets = append(routes.subnets, subnet.Masked())
		}
	}
	return routes
}

func NormalizeName(name string) string {
	return strings.Trim(strings.ToLower(strings.TrimSpace(name)), ".")
}

func (r *Routes) MatchHost(host string) bool {
	if r == nil {
		return false
	}
	host = NormalizeName(host)
	if host == "" {
		return false
	}
	if _, ok := r.names[host]; ok {
		return true
	}
	for _, suffix := range r.suffixes {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

// MatchAddr reports a peer address, or an address inside an approved subnet
// unless it is also inside a network this device is attached to: a LAN numbered
// like a remote subnet stays local, and an explicit rule can still claim it.
func (r *Routes) MatchAddr(addr netip.Addr) bool {
	if r == nil || !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	if _, ok := r.addrs[addr]; ok {
		return true
	}
	for _, subnet := range r.subnets {
		if subnet.Contains(addr) {
			return !isLocalNetwork(addr)
		}
	}
	return false
}

func (r *Routes) Empty() bool {
	return r == nil || (len(r.suffixes) == 0 && len(r.names) == 0 && len(r.addrs) == 0 && len(r.subnets) == 0)
}

// Source supplies the latest routes of a running outbound.
type Source interface {
	Routes() *Routes
}

type entry struct {
	id     uint64
	source Source
}

var (
	nextID    atomic.Uint64
	sourcesMu sync.RWMutex
	sources   = map[string]entry{}
)

// Register makes source the tailnet of the outbound called name. The returned
// function removes it unless a newer registration replaced it.
func Register(name string, source Source) func() {
	id := nextID.Add(1)
	sourcesMu.Lock()
	sources[name] = entry{id: id, source: source}
	sourcesMu.Unlock()
	return func() {
		sourcesMu.Lock()
		if current, ok := sources[name]; ok && current.id == id {
			delete(sources, name)
		}
		sourcesMu.Unlock()
	}
}

func Lookup(name string) *Routes {
	sourcesMu.RLock()
	current, ok := sources[name]
	sourcesMu.RUnlock()
	if !ok {
		return nil
	}
	return current.source.Routes()
}
