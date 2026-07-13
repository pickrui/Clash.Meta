package outbound

import (
	"strings"
	"testing"
)

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
