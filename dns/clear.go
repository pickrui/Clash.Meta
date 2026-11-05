package dns

import (
	"reflect"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
)

// ClearAll resets learned DNS state without closing the resolver or its callers.
func ClearAll() {
	var pending []*Resolver
	for _, root := range []resolver.Resolver{resolver.DefaultResolver, resolver.SystemResolver} {
		switch root := root.(type) {
		case *Resolver:
			pending = append(pending, root)
		case Resolvers:
			pending = append(pending, root.Resolver, root.ProxyResolver, root.DirectResolver)
		case *Resolvers:
			if root != nil {
				pending = append(pending, root.Resolver, root.ProxyResolver, root.DirectResolver)
			}
		}
	}
	visited := make(map[*Resolver]struct{})
	reset := make(map[dnsClient]struct{})
	for len(pending) != 0 {
		r := pending[0]
		pending = pending[1:]
		if r == nil {
			continue
		}
		if _, seen := visited[r]; seen {
			continue
		}
		visited[r] = struct{}{}
		r.stateMu.Lock()
		r.generation++
		r.ClearCache()
		r.stateMu.Unlock()
		r.forEachClient(func(c dnsClient) { resetClientOnce(c, reset, true) })
		pending = append(pending, r.defaultResolver)
	}
	answeredBy.Clear()
}

func (r *Resolver) forEachClient(visit func(dnsClient)) {
	for _, c := range r.main {
		visit(c)
	}
	for _, c := range r.fallback {
		visit(c)
	}
	for _, policy := range r.policy {
		policy.forEachClient(visit)
	}
}

func resetClientOnce(c dnsClient, seen map[dnsClient]struct{}, clear bool) {
	raw := rawTransport(c)
	value := reflect.ValueOf(raw)
	if !value.IsValid() || value.Kind() == reflect.Pointer && value.IsNil() {
		return
	}
	if value.Comparable() {
		if _, done := seen[raw]; done {
			return
		}
		seen[raw] = struct{}{}
	}
	if clear {
		if system, ok := raw.(*systemClient); ok {
			system.mu.Lock()
			system.lastFlush = time.Time{}
			system.mu.Unlock()
		}
	}
	raw.ResetConnection()
}
