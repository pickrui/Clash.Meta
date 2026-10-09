package outbound

import (
	"github.com/metacubex/mihomo/component/ech"
	"testing"
)

func TestSnellHTTP3Options(t *testing.T) {
	config, _, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		transport string
		identity  int
		legacy    bool
		version   int
		valid     bool
	}{
		{"", 2, false, 4, true},
		{"tcp", 1, true, 4, true},
		{"h3", 2, false, 4, true},
		{"auto", 2, false, 4, true},
		{"quic", 2, false, 4, false},
		{"h3", 1, false, 4, false},
		{"auto", 2, true, 4, false},
		{"h3", 2, false, 3, false},
	} {
		adapter, err := NewSnell(SnellOption{
			Name: "fixture", Server: "127.0.0.1", Port: 443, Psk: "fixture", Version: tc.version,
			ObfsOpts: map[string]any{"mode": "ech-tls", "ech-config": config, "transport": tc.transport, "identity-version": tc.identity, "legacy-fallback": tc.legacy},
		})
		if (err == nil) != tc.valid {
			t.Fatalf("%+v: %v", tc, err)
		}
		if err == nil {
			_ = adapter.Close()
		}
	}
}
