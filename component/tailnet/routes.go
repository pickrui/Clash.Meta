// Package tailnet publishes the destinations a Tailscale outbound can reach, so
// a TAILNET rule follows the outbound's network map without a config reload.
package tailnet

import (
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
)

// Routes is an immutable snapshot of one tailnet's known peers.
type Routes struct {
	suffixes []string
	names    map[string]struct{}
	addrs    map[netip.Addr]struct{}
}

func NewRoutes(suffixes []string, names []string, addrs []netip.Addr) *Routes {
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

func (r *Routes) MatchAddr(addr netip.Addr) bool {
	if r == nil || !addr.IsValid() {
		return false
	}
	_, ok := r.addrs[addr.Unmap()]
	return ok
}

func (r *Routes) Empty() bool {
	return r == nil || (len(r.suffixes) == 0 && len(r.names) == 0 && len(r.addrs) == 0)
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
