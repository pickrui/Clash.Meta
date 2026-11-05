//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"

	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/tailscale/ipn"
)

var (
	errTailscaleControlLoop = errors.New("tailscale control traffic cannot route through a tailnet")
	errTailscaleControlSelf = errors.New("tailscale control server lies in its own routes")
)

// tailscaleControlRoute sends a network's control connections through the
// profile's rules, as an app's connection to that server would go, so a
// control server blocked on the direct path is reached like other sites. DERP
// and peer traffic keep the system dialer. tsnet dials resolved addresses, so
// the server is recognized by the addresses its own lookups returned.
type tailscaleControlRoute struct {
	host    string
	rules   C.RuleDialer
	proxies interface{ Proxies() map[string]C.Proxy }
	system  C.Dialer

	mu    sync.Mutex
	addrs map[netip.Addr]struct{}
}

func newTailscaleControlRoute(option TailscaleOption, system C.Dialer) *tailscaleControlRoute {
	route := &tailscaleControlRoute{system: system, addrs: map[netip.Addr]struct{}{}}
	// An explicit dialer or egress keeps all of the network's traffic on it.
	if option.DialerProxy == "" && option.DialerForAPI == nil && option.Interface == "" && option.RoutingMark == 0 {
		route.rules, _ = option.NewTunnel().(C.RuleDialer)
		route.proxies, _ = option.NewTunnel().(interface{ Proxies() map[string]C.Proxy })
	}
	controlURL := option.ControlURL
	if controlURL == "" {
		controlURL = ipn.DefaultControlURL
	}
	if u, err := url.Parse(controlURL); err == nil {
		route.host = strings.ToLower(u.Hostname())
	}
	if addr, err := netip.ParseAddr(route.host); err == nil {
		route.addrs[addr.Unmap()] = struct{}{}
		route.host = ""
	}
	return route
}

func (r *tailscaleControlRoute) learn(host string, addrs []netip.Addr) {
	if r.host == "" || !strings.EqualFold(strings.TrimSuffix(host, "."), r.host) {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.addrs)+len(addrs) > 64 {
		clear(r.addrs)
	}
	for _, addr := range addrs {
		r.addrs[addr.Unmap()] = struct{}{}
	}
}

func (r *tailscaleControlRoute) destination(address string) *C.Metadata {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return nil
	}
	metadata := &C.Metadata{Host: r.host, DstPort: uint16(port)}
	if addr, err := netip.ParseAddr(host); err == nil {
		addr = addr.Unmap()
		r.mu.Lock()
		_, ok := r.addrs[addr]
		r.mu.Unlock()
		if !ok {
			return nil
		}
		metadata.DstIP = addr
		return metadata
	}
	if r.host == "" || !strings.EqualFold(host, r.host) {
		return nil
	}
	return metadata
}

func (r *tailscaleControlRoute) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var metadata *C.Metadata
	if r.rules != nil && strings.HasPrefix(network, "tcp") {
		metadata = r.destination(address)
	}
	if metadata == nil {
		return r.system.DialContext(ctx, network, address)
	}
	conn, err := r.rules.DialTCPByRules(ctx, metadata, func(proxy C.Proxy, rule C.Rule) error {
		if !r.reachesTailnet(proxy, metadata) {
			return nil
		}
		// tailscaled reaches control outside the routes it learns from
		// control, so only an explicit rule into a tailnet is refused.
		if rule != nil && rule.RuleType() == C.Tailnet {
			return errTailscaleControlSelf
		}
		return errTailscaleControlLoop
	})
	if errors.Is(err, errTailscaleControlSelf) {
		return r.system.DialContext(ctx, network, address)
	}
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// reachesTailnet follows group selections and dialer-proxy hops, which a
// chain through a tailnet takes.
func (r *tailscaleControlRoute) reachesTailnet(proxy C.Proxy, metadata *C.Metadata) bool {
	var proxies map[string]C.Proxy
	if r.proxies != nil {
		proxies = r.proxies.Proxies()
	}
	pending := []C.Proxy{proxy}
	for hops := 0; len(pending) > 0 && hops < 64; hops++ {
		adapter := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		for ; adapter != nil; adapter = adapter.Unwrap(metadata, false) {
			if adapter.Type() == C.Tailscale {
				return true
			}
			if dialer, ok := proxies[adapter.ProxyInfo().DialerProxy]; ok {
				pending = append(pending, dialer)
			}
		}
	}
	return false
}
