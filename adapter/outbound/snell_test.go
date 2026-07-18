package outbound

import (
	"strings"
	"testing"

	"github.com/metacubex/mihomo/component/ech"
)

func TestSnellECHTLSUsesRawTLSWithoutPath(t *testing.T) {
	echConfig, _, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}

	adapter, err := NewSnell(SnellOption{
		Name:    "snell",
		Server:  "origin.example.com",
		Port:    443,
		Psk:     "password",
		Version: 4,
		ObfsOpts: map[string]any{
			"mode":       "ech-tls",
			"ech-config": echConfig,
		},
	})
	if err != nil {
		t.Fatalf("NewSnell() error = %v", err)
	}
	defer adapter.Close()

	if adapter.echTLS == nil || adapter.echTLS.ECH == nil {
		t.Fatal("ECH TLS config was not initialized")
	}
	if len(adapter.echTLS.NextProtos) != 1 || adapter.echTLS.NextProtos[0] != snellECHTLSALPN {
		t.Fatalf("NextProtos = %q, want [%q]", adapter.echTLS.NextProtos, snellECHTLSALPN)
	}
}

func TestSnellRejectsAnyTLSObfs(t *testing.T) {
	_, err := NewSnell(SnellOption{
		Name:   "snell",
		Server: "127.0.0.1",
		Port:   443,
		Psk:    "password",
		ObfsOpts: map[string]any{
			"mode":     "anytls",
			"password": "outer-password",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "obfs mode error: anytls") {
		t.Fatalf("NewSnell() error = %v, want unsupported anytls obfs", err)
	}
}

func TestSnellRejectsDisabledIdentityForECHTLS(t *testing.T) {
	_, err := NewSnell(SnellOption{
		Name:               "snell",
		Server:             "127.0.0.1",
		Port:               443,
		Psk:                "password",
		Version:            4,
		IdentityConfigured: true,
		ObfsOpts: map[string]any{
			"mode":       "ech-tls",
			"path":       "/snell",
			"ech-config": "invalid",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "identity cannot be disabled") {
		t.Fatalf("NewSnell() error = %v, want disabled identity error", err)
	}
}
