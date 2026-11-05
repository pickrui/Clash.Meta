package outbound

import (
	"context"
	"net"
	"sync"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/dns"
)

type nodeDNS struct {
	mu      sync.Mutex
	servers []dns.NameServer
	ipv6    bool
	current *dns.Resolver
	closed  bool
}

func (d *nodeDNS) get(ctx context.Context) (resolver.Resolver, error) {
	if d == nil {
		return resolver.DefaultResolver, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if d.current == nil {
		d.current = dns.NewResolver(dns.Config{Main: d.servers, IPv6: d.ipv6}).Resolver
		d.servers = nil
	}
	return d.current, nil
}

func (d *nodeDNS) close() {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	d.current.CloseQueries()
	d.current = nil
	d.servers = nil
}
