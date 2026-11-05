package adapter_test

import (
	"encoding/json"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/adapter/provider"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/stretchr/testify/require"
)

func TestProxyJSONKeepsGroupAndProviderPayloads(t *testing.T) {
	members := []C.Proxy{
		adapter.NewProxy(outbound.NewBase(outbound.BaseOption{Name: "香港 <&>", Type: C.Direct, UDP: true})),
		adapter.NewProxy(outbound.NewBase(outbound.BaseOption{Name: "東京", Type: C.Reject})),
	}
	hc := provider.NewHealthCheck(members, C.DefaultTestURL, 0, 0, true, nil)
	memberProvider, err := provider.NewCompatibleProvider("members", members, hc)
	require.NoError(t, err)
	t.Cleanup(func() { _ = memberProvider.Close() })
	providers := []P.ProxyProvider{memberProvider}
	option := outboundgroup.GroupCommonOption{Name: "策略 <&>", Icon: "https://icon.test/?a=&b", Hidden: true, URL: C.DefaultTestURL, ExpectedStatus: "200-399"}
	for _, kind := range []string{"select", "url-test", "fallback", "load-balance"} {
		t.Run(kind, func(t *testing.T) {
			var group outboundgroup.ProxyGroup
			var err error
			switch kind {
			case "select":
				group, err = outboundgroup.NewSelector(option, outboundgroup.SelectorOption{DefaultSelected: members[1].Name()}, members[0], providers)
			case "url-test":
				group, err = outboundgroup.NewURLTest(option, outboundgroup.URLTestOption{}, members[0], providers)
			case "fallback":
				group, err = outboundgroup.NewFallback(option, outboundgroup.FallbackOption{}, members[0], providers)
			case "load-balance":
				group, err = outboundgroup.NewLoadBalance(option, outboundgroup.LoadBalanceOption{}, members[0], providers)
			}
			require.NoError(t, err)
			t.Cleanup(func() { _ = group.Close() })
			inner, err := group.MarshalJSON()
			require.NoError(t, err)
			var want map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(inner, &want))
			proxy := adapter.NewProxy(group)
			data, err := json.Marshal(map[string]C.Proxy{proxy.Name(): proxy})
			require.NoError(t, err)
			var list map[string]map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(data, &list))
			for field, value := range want {
				require.Equal(t, string(value), string(list[proxy.Name()][field]), field)
			}
			require.Equal(t, "[]", string(list[proxy.Name()]["history"]))
			require.Equal(t, "{}", string(list[proxy.Name()]["extra"]))
			providerHC := provider.NewHealthCheck([]C.Proxy{proxy}, C.DefaultTestURL, 0, 0, true, nil)
			pd, err := provider.NewCompatibleProvider("groups", []C.Proxy{proxy}, providerHC)
			require.NoError(t, err)
			t.Cleanup(func() { _ = pd.Close() })
			encoded, err := json.Marshal(pd)
			require.NoError(t, err)
			var payload struct {
				Proxies []map[string]json.RawMessage `json:"proxies"`
			}
			require.NoError(t, json.Unmarshal(encoded, &payload))
			require.Equal(t, []map[string]json.RawMessage{list[proxy.Name()]}, payload.Proxies)
		})
	}
}
