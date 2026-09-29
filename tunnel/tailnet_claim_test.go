package tunnel

import (
	"context"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/tailnet"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/rules/common"
	RW "github.com/metacubex/mihomo/rules/wrapper"
)

type claimTestProxy struct {
	C.Proxy
	name        string
	adapterType C.AdapterType
}

func (p *claimTestProxy) Name() string                     { return p.name }
func (p *claimTestProxy) Type() C.AdapterType              { return p.adapterType }
func (p *claimTestProxy) SupportUDP() bool                 { return true }
func (p *claimTestProxy) Unwrap(*C.Metadata, bool) C.Proxy { return nil }

type claimTestRoutes struct{ routes *tailnet.Routes }

func (s claimTestRoutes) Routes() *tailnet.Routes { return s.routes }

func TestTailnetClaimFollowsTheFirstResolution(t *testing.T) {
	oldProxies, oldProviders := Proxies(), ProvidersSnapshot()
	oldRules, oldSubRules, oldRuleProviders := rules, subRules, ruleProviders
	oldLookup := directLookup
	t.Cleanup(func() {
		UpdateProxies(oldProxies, oldProviders)
		UpdateRules(oldRules, oldSubRules, oldRuleProviders)
		directLookup = oldLookup
	})
	home := &claimTestProxy{name: "Home", adapterType: C.Tailscale}
	direct := &claimTestProxy{name: "DIRECT", adapterType: C.Direct}
	remote := &claimTestProxy{name: "Proxy", adapterType: C.Shadowsocks}
	pass := &claimTestProxy{name: "Skip", adapterType: C.Pass}
	UpdateProxies(map[string]C.Proxy{"Home": home, "DIRECT": direct, "Proxy": remote, "Skip": pass}, map[string]P.ProxyProvider{})

	unregister := tailnet.Register("Home", claimTestRoutes{tailnet.NewRoutes(
		nil, nil, nil, []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
	)})
	defer unregister()

	mustIPCIDR := func(cidr, adapter string) C.Rule {
		rule, err := common.NewIPCIDR(cidr, adapter)
		if err != nil {
			t.Fatal(err)
		}
		return rule
	}
	tailnetRule := common.NewTailnet("Home", "Home")
	wrapped := RW.NewRuleWrapper(common.NewTailnet("Home", "Home"))

	for name, test := range map[string]struct {
		rules        []C.Rule
		resolvesTo   string
		want         C.Proxy
		wantRule     C.Rule
		ruleResolves int
		directLooks  int
	}{
		"a later IP rule resolves into the subnet": {
			rules:      []C.Rule{tailnetRule, mustIPCIDR("198.51.0.0/16", "Proxy"), common.NewMatch("Proxy")},
			resolvesTo: "198.51.100.7", want: home, wantRule: tailnetRule, ruleResolves: 1,
		},
		"an address outside the subnets keeps the profile's choice": {
			rules:      []C.Rule{tailnetRule, mustIPCIDR("10.0.0.0/8", "DIRECT"), common.NewMatch("Proxy")},
			resolvesTo: "203.0.113.7", want: remote, ruleResolves: 1,
		},
		"DIRECT is checked with its own lookup": {
			rules:      []C.Rule{tailnetRule, common.NewMatch("DIRECT")},
			resolvesTo: "198.51.100.7", want: home, wantRule: tailnetRule, directLooks: 1,
		},
		"an unclaimed DIRECT host keeps its metadata": {
			rules:      []C.Rule{tailnetRule, common.NewMatch("DIRECT")},
			resolvesTo: "203.0.113.7", want: direct, directLooks: 1,
		},
		"a proxied host adds no DNS query": {
			rules:      []C.Rule{tailnetRule, common.NewMatch("Proxy")},
			resolvesTo: "198.51.100.7", want: remote,
		},
		"a rule ahead of the network still wins": {
			rules:      []C.Rule{common.NewDomain("nas.example.com", "DIRECT"), tailnetRule, common.NewMatch("Proxy")},
			resolvesTo: "198.51.100.7", want: direct,
		},
		"no matching rule falls back to DIRECT after the check": {
			rules:      []C.Rule{tailnetRule},
			resolvesTo: "198.51.100.7", want: home, wantRule: tailnetRule, directLooks: 1,
		},
		"a top-level rule is returned wrapped": {
			rules:      []C.Rule{wrapped, common.NewMatch("DIRECT")},
			resolvesTo: "198.51.100.7", want: home, wantRule: wrapped, directLooks: 1,
		},
		"a nested rule without a target never claims": {
			rules:      []C.Rule{common.NewTailnet("Home", ""), common.NewMatch("DIRECT")},
			resolvesTo: "198.51.100.7", want: direct,
		},
		"a PASS target is not taken by a claim": {
			rules:      []C.Rule{common.NewTailnet("Home", "Skip"), common.NewMatch("DIRECT")},
			resolvesTo: "198.51.100.7", want: direct, directLooks: 1,
		},
	} {
		t.Run(name, func(t *testing.T) {
			UpdateRules(test.rules, nil, nil)
			metadata := &C.Metadata{NetWork: C.TCP, Host: "nas.example.com", DstPort: 443}
			ruleResolves, directLooks := 0, 0
			directLookup = func(context.Context, string) (netip.Addr, error) {
				directLooks++
				return netip.MustParseAddr(test.resolvesTo), nil
			}
			helper := C.RuleMatchHelper{ResolveIP: func() {
				if !metadata.Resolved() {
					ruleResolves++
					metadata.DstIP = netip.MustParseAddr(test.resolvesTo)
				}
			}}
			proxy, rule, err := match(metadata, helper)
			if err != nil {
				t.Fatal(err)
			}
			if proxy != test.want {
				t.Fatalf("routed to %s", proxy.Name())
			}
			if ruleResolves != test.ruleResolves || directLooks != test.directLooks {
				t.Fatalf("resolved %d times in rules and %d for DIRECT", ruleResolves, directLooks)
			}
			if test.wantRule != nil && rule != test.wantRule {
				t.Fatalf("matched by %v", rule)
			}
			if proxy == direct && test.directLooks > 0 && metadata.Resolved() {
				t.Fatal("an unclaimed DIRECT host was given an address")
			}
		})
	}
	if hits := wrapped.HitCount(); hits != 1 {
		t.Fatalf("the claimed rule counted %d hits", hits)
	}
}
