package adapter

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestProviderNodeRefusalKeepsTheName(t *testing.T) {
	previous := ProviderNodeRefused
	t.Cleanup(func() { ProviderNodeRefused = previous })
	ProviderNodeRefused = func(proxy C.ProxyAdapter) bool {
		return proxy.ProxyInfo().DialerProxy != "" && proxy.Addr() == "refused.example:443"
	}
	node := func(server string, extra map[string]any) map[string]any {
		mapping := map[string]any{
			"name": "N", "type": "ss", "server": server, "port": 443,
			"cipher": "aes-128-gcm", "password": "x",
		}
		for key, value := range extra {
			mapping[key] = value
		}
		return mapping
	}
	dialing := map[string]any{"dialer-proxy": "P"}
	parse := func(mapping map[string]any, options ...ProxyOption) C.Proxy {
		t.Helper()
		proxy, err := ParseProxy(mapping, options...)
		if err != nil {
			t.Fatal(err)
		}
		return proxy
	}
	fromProvider := WithProviderName("Home")

	refused := parse(node("refused.example", dialing), fromProvider)
	if refused.Type() != C.Reject || refused.Name() != "N" {
		t.Fatalf("got %s %s", refused.Type(), refused.Name())
	}
	clone, err := refused.(*Proxy).WithDialerProxy("Q")
	if err != nil || clone.Type() != C.Reject {
		t.Fatalf("a refused node's clone = %v, %v", clone, err)
	}

	plain := parse(node("refused.example", nil), fromProvider)
	if plain.Type() != C.Shadowsocks {
		t.Fatalf("a node without a dialer = %s", plain.Type())
	}
	clone, err = plain.(*Proxy).WithDialerProxy("P")
	if err != nil || clone.Type() != C.Reject {
		t.Fatalf("a landing group's clone = %v, %v", clone, err)
	}

	if got := parse(node("public.example", dialing), fromProvider); got.Type() != C.Shadowsocks {
		t.Fatalf("a public node = %s", got.Type())
	}
	if got := parse(node("refused.example", dialing)); got.Type() != C.Shadowsocks {
		t.Fatalf("a node outside a provider = %s", got.Type())
	}
	ProviderNodeRefused = nil
	if got := parse(node("refused.example", dialing), fromProvider); got.Type() != C.Shadowsocks {
		t.Fatalf("without a check = %s", got.Type())
	}
}
