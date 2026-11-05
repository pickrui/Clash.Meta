package provider

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
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
	previous := tunnel
	SetTunnel(&concurrentRuleTunnel{})
	defer SetTunnel(previous)
	p := NewRuleSetProvider("test", P.Domain, P.YamlRule, 0, resource.NewFileVehicle(filepath.Join(t.TempDir(), "rules.yaml")), nil, nil, nil).(*RuleSetProvider)
	defer p.Close()
	var group sync.WaitGroup
	group.Go(func() {
		for index := range 100 {
			_, _, err := p.SideUpdate([]byte(fmt.Sprintf("payload:\n  - '%d.example.com'\n", index)))
			if err != nil {
				t.Error(err)
			}
		}
	})
	group.Go(func() {
		for range 1000 {
			_ = p.Count()
			_ = p.Match(&C.Metadata{Host: "1.example.com"}, C.RuleMatchHelper{})
			_, _ = p.MarshalJSON()
		}
	})
	group.Wait()
	if p.Count() != 1 || !p.Match(&C.Metadata{Host: "99.example.com"}, C.RuleMatchHelper{}) {
		t.Fatal("last update was not published")
	}
}
