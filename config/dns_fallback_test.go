package config

import (
	"encoding/json"
	"gopkg.in/yaml.v3"
	"testing"
)

func TestParseDNSFallbackLazyQuery(t *testing.T) {
	for _, decode := range []struct {
		name string
		fn   func([]byte, any) error
	}{{"JSON", json.Unmarshal}, {"YAML", yaml.Unmarshal}} {
		for _, value := range []string{"false", "true"} {
			t.Run(decode.name+"/"+value, func(t *testing.T) {
				raw := DefaultRawConfig()
				input := []byte(`{"dns":{"enable":true,"nameserver":["192.0.2.1"],"fallback":["192.0.2.2"],"fallback-lazy-query":` + value + `,"fallback-filter":{"geoip":false}}}`)
				if err := decode.fn(input, raw); err != nil {
					t.Fatal(err)
				}
				parsed, err := parseDNS(raw, nil)
				if err != nil {
					t.Fatal(err)
				}
				if parsed.FallbackLazyQuery != (value == "true") {
					t.Fatalf("fallback lazy query changed: %v", parsed.FallbackLazyQuery)
				}
			})
		}
	}
}
