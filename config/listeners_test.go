package config

import (
	"strings"
	"testing"
)

func TestParseListenersRejectsDuplicateNames(t *testing.T) {
	config := &RawConfig{Listeners: []map[string]any{
		{"name": "shared", "type": "http", "listen": "127.0.0.1", "port": 1080},
		{"name": "shared", "type": "socks", "listen": "127.0.0.1", "port": 1081},
	}}
	if _, err := parseListeners(config); err == nil || !strings.Contains(err.Error(), "duplicate name") {
		t.Fatalf("duplicate listeners: %v", err)
	}
}

func TestParseListenersAcceptsNamesMatchingConfigKeys(t *testing.T) {
	for _, name := range []string{"name", "type", "listen", "port"} {
		result, err := parseListeners(&RawConfig{Listeners: []map[string]any{{"name": name, "type": "http", "listen": "127.0.0.1", "port": 1080}}})
		if err != nil {
			t.Errorf("name=%s: %v", name, err)
			continue
		}
		if len(result) != 1 || result[name].Name() != name {
			t.Fatalf("missing listener %s", name)
		}
	}
}

func TestParseListenersIdentifiesInvalidEntry(t *testing.T) {
	_, err := parseListeners(&RawConfig{Listeners: []map[string]any{{"name": "bad"}}})
	if err == nil || !strings.HasPrefix(err.Error(), "listener 0:") {
		t.Fatalf("invalid entry: %v", err)
	}
}
