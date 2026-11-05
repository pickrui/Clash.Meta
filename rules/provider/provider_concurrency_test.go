package provider

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/rules/common"
)

type concurrentRuleTunnel struct {
	callback utils.Callback[P.RuleProvider]
}

func (t *concurrentRuleTunnel) Providers() map[string]P.ProxyProvider    { return nil }
func (t *concurrentRuleTunnel) RuleProviders() map[string]P.RuleProvider { return nil }
func (t *concurrentRuleTunnel) RuleUpdateCallback() *utils.Callback[P.RuleProvider] {
	return &t.callback
}
func TestRuleStrategyConcurrentUpdate(t *testing.T) {
	for _, tc := range []struct {
		name     string
		behavior P.RuleBehavior
		ip       bool
	}{
		{"domain", P.Domain, false},
		{"classical_domains", P.Classical, false},
		{"classical_ips", P.Classical, true},
	} {
		t.Run(tc.name, func(t *testing.T) { testRuleStrategyConcurrentUpdate(t, tc.behavior, tc.ip) })
	}
}

func testRuleStrategyConcurrentUpdate(t *testing.T, behavior P.RuleBehavior, ip bool) {
	previous := tunnel
	SetTunnel(&concurrentRuleTunnel{})
	defer SetTunnel(previous)
	parse := func(tp, payload, target string, _ []string, _ map[string][]C.Rule) (C.Rule, error) {
		if tp == "IP-CIDR" {
			return common.NewIPCIDR(payload, target, common.WithIPCIDRNoResolve(true))
		}
		if tp != "DOMAIN" {
			return nil, fmt.Errorf("unexpected rule type: %s", tp)
		}
		return common.NewDomain(payload, target), nil
	}
	p := NewRuleSetProvider("test", behavior, P.YamlRule, 0, resource.NewFileVehicle(filepath.Join(t.TempDir(), "rules.yaml")), nil, nil, parse).(*RuleSetProvider)
	defer p.Close()
	var group sync.WaitGroup
	group.Go(func() {
		for index := range 100 {
			data := []byte("payload:\n")
			prefix := ""
			if behavior == P.Classical {
				prefix = "DOMAIN,"
			}
			for rule := range 32 {
				if ip {
					data = fmt.Appendf(data, "  - 'IP-CIDR,10.%d.%d.0/25,no-resolve'\n", index, rule)
				} else {
					data = fmt.Appendf(data, "  - '%s%d-%d.example.com'\n", prefix, index, rule)
				}
			}
			_, _, err := p.SideUpdate(data)
			if err != nil {
				t.Error(err)
			}
		}
	})
	group.Go(func() {
		for range 1000 {
			_ = p.Count()
			_ = p.Match(&C.Metadata{Host: "1-0.example.com", DstIP: netip.MustParseAddr("10.1.0.1")}, C.RuleMatchHelper{})
			_, _ = p.MarshalJSON()
		}
	})
	group.Wait()
	if p.Count() != 32 || !p.Match(&C.Metadata{Host: "99-0.example.com", DstIP: netip.MustParseAddr("10.99.0.1")}, C.RuleMatchHelper{}) || p.Match(&C.Metadata{Host: "98-0.example.com", DstIP: netip.MustParseAddr("10.98.0.1")}, C.RuleMatchHelper{}) {
		t.Fatal("last update was not published")
	}
}
