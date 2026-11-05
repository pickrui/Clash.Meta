package outbound

import (
	"fmt"
	"strings"
	"testing"
)

func TestShadowSocksRestlsOptions(t *testing.T) {
	for _, test := range []struct {
		name                        string
		extra                       map[string]any
		skip, pin, force, wantError bool
	}{
		{name: "defaults"},
		{name: "skip", extra: map[string]any{"skip-cert-verify": true}, skip: true},
		{name: "pin", extra: map[string]any{"fingerprint": fmt.Sprintf("%064x", 1)}, skip: true, pin: true},
		{name: "force_tls12", extra: map[string]any{"force-tls12": true}, force: true},
		{name: "invalid_pin", extra: map[string]any{"fingerprint": "not-a-sha256"}, wantError: true},
		{name: "browser_is_not_pin", extra: map[string]any{"fingerprint": "chrome"}, wantError: true},
		{name: "invalid_script", extra: map[string]any{"restls-script": "40000"}, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := map[string]any{"host": "restls.test", "password": "restls-password", "version-hint": "tls12"}
			for key, value := range test.extra {
				options[key] = value
			}
			client, err := NewShadowSocks(ShadowSocksOption{Name: "restls-test", Server: "127.0.0.1", Port: 443,
				Cipher: "chacha20-ietf-poly1305", Password: "ss-password", ClientFingerprint: "firefox", Plugin: "restls", PluginOpts: options})
			if test.wantError {
				if err == nil || !strings.Contains(err.Error(), "initialize restls-plugin error") {
					t.Fatalf("plugin error=%v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			config := client.restlsConfig
			if config == nil {
				t.Fatal("Restls configuration missing")
			}
			if config.InsecureSkipVerify != test.skip || (config.VerifyConnection != nil) != test.pin || config.ForceTLS12 != test.force {
				t.Fatalf("TLS options not forwarded: skip=%v pin=%v forceTLS12=%v", config.InsecureSkipVerify, config.VerifyConnection != nil, config.ForceTLS12)
			}
			if config.ServerName != "restls.test" || config.ClientID.Load().Client != "Firefox" || config.ClientSessionCache == nil {
				t.Fatal("existing plugin options changed")
			}
		})
	}
}
