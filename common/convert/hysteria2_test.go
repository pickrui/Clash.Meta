package convert_test

import (
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/common/convert"
	"github.com/stretchr/testify/require"
)

func TestHysteria2PortHoppingImport(t *testing.T) {
	for _, tc := range []struct{ uri, server, port, ports string }{
		{"hysteria2://secret@example.com:443,5000-6000/?sni=example.com#hop", "example.com", "443", "443,5000-6000"},
		{"hy2://secret@192.0.2.1:5000-5002/#range", "192.0.2.1", "5000", "5000-5002"},
		{"hy2://secret@example.com:65535-65535/#max", "example.com", "65535", "65535-65535"},
		{"hy2://secret@[2001:db8::1]:8443/#ipv6", "2001:db8::1", "8443", ""},
	} {
		t.Run(tc.server+tc.ports, func(t *testing.T) {
			proxies, err := convert.ConvertsV2Ray([]byte(tc.uri))
			require.NoError(t, err)
			require.Len(t, proxies, 1)
			p := proxies[0]
			require.Equal(t, tc.server, p["server"])
			require.Equal(t, tc.port, p["port"])
			require.Equal(t, "secret", p["password"])
			if tc.ports != "" {
				require.Equal(t, tc.ports, p["ports"])
			} else {
				require.NotContains(t, p, "ports")
			}
			proxy, err := adapter.ParseProxy(p)
			require.NoError(t, err)
			require.NoError(t, proxy.Close())
		})
	}
}

func TestHysteria2RealmImport(t *testing.T) {
	for _, scheme := range []string{"hysteria2+realm", "hy2+realm"} {
		t.Run(scheme, func(t *testing.T) {
			proxies, err := convert.ConvertsV2Ray([]byte(scheme + "://t%2Bok%3Den@rendezvous.example.com:8443/rid%2F42?auth=let%2Bmein&stun=stun1:3478&stun=stun2:3478&sni=example.com#realm"))
			require.NoError(t, err)
			require.Len(t, proxies, 1)
			p := proxies[0]
			require.Equal(t, "hysteria2", p["type"])
			require.Equal(t, "let+mein", p["password"])
			require.Equal(t, map[string]any{"enable": true, "server-url": "https://rendezvous.example.com:8443", "token": "t+ok=en", "realm-id": "rid/42", "stun-servers": []string{"stun1:3478", "stun2:3478"}}, p["realm-opts"])
			proxy, err := adapter.ParseProxy(p)
			require.NoError(t, err)
			require.NoError(t, proxy.Close())
		})
	}
}

func TestHysteria2ImportKeepsInvalidPortsRejected(t *testing.T) {
	for _, uri := range []string{"hy2://secret@example.com:,443", "hy2://secret@example.com:443,broken", "hy2://secret@example.com:70000-70001", "hy2://secret@example.com:443,65536", "hy2://secret@example.com:0-443", "hy2://secret@example.com:443,", "hy2://secret@example.com:6000-5000"} {
		proxies, err := convert.ConvertsV2Ray([]byte(uri))
		if err != nil {
			continue
		}
		require.Len(t, proxies, 1)
		proxy, err := adapter.ParseProxy(proxies[0])
		if err == nil {
			_ = proxy.Close()
			t.Errorf("invalid ports accepted: %s", uri)
		}
	}
}
