package listener

import (
	"testing"

	LC "github.com/metacubex/mihomo/listener/config"
	IN "github.com/metacubex/mihomo/listener/inbound"
)

func TestParseRestlsShadowSocksListener(t *testing.T) {
	mapping := map[string]any{"type": "shadowsocks", "name": "restls-test", "listen": "127.0.0.1", "port": 0, "udp": false, "cipher": "none", "password": "ss-password",
		"res-tls": map[string]any{"enable": true, "dest": "camouflage.test:443", "password": "restls-password", "restls-script": "300?100<1,400~100", "min-record-len": 32, "rate-limit": 32768, "proxy": "camouflage-route"}}
	listener, err := ParseListener(mapping)
	if err != nil {
		t.Fatal(err)
	}
	// A parsed listener can be closed safely before binding, including validation-only calls.
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	config := listener.Config().(*IN.ShadowSocksOption)
	want := LC.ResTLS{Enable: true, Dest: "camouflage.test:443", Password: "restls-password", RestlsScript: "300?100<1,400~100", MinRecordLen: 32, RateLimit: 32768, Proxy: "camouflage-route"}
	if got := config.ResTLS.Build(); got != want {
		t.Fatalf("parsed options=%+v", got)
	}
	for _, change := range []struct {
		name   string
		mutate func(*IN.ResTLS)
	}{
		{"rate_limit", func(r *IN.ResTLS) { r.RateLimit++ }}, {"proxy", func(r *IN.ResTLS) { r.Proxy = "different-route" }},
		{"script", func(r *IN.ResTLS) { r.RestlsScript = "1500" }}, {"enabled", func(r *IN.ResTLS) { r.Enable = false }},
	} {
		t.Run(change.name, func(t *testing.T) {
			other := *config
			change.mutate(&other.ResTLS)
			if config.Equal(&other) {
				t.Fatal("listener reload ignored changed Restls configuration")
			}
		})
	}
}

func TestParseRestlsRejectsInvalidConfiguration(t *testing.T) {
	for _, test := range []struct {
		name      string
		options   map[string]any
		wantError bool
	}{
		{"missing_destination", map[string]any{"enable": true, "dest": "", "password": "test"}, true},
		{"invalid_script", map[string]any{"enable": true, "dest": "camouflage.test", "password": "test", "restls-script": "40000"}, true},
		{"disabled_options", map[string]any{"enable": false, "dest": "", "password": "test", "restls-script": "40000"}, false},
		{"unchanged_plain_shadowsocks", nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			mapping := map[string]any{"type": "shadowsocks", "name": "restls-test", "listen": "127.0.0.1", "port": 0, "cipher": "none", "password": "password"}
			if test.options != nil {
				mapping["res-tls"] = test.options
			}
			listener, err := ParseListener(mapping)
			if (err != nil) != test.wantError {
				t.Fatalf("parse error=%v wantError=%v", err, test.wantError)
			}
			if err == nil {
				if err := listener.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
