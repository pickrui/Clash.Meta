package config

import (
	"encoding/json"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestRawConfigJSONMatchesYAMLFieldNames(t *testing.T) {
	input := []byte(`{"tun":{"auto-detect-interface":true},"experimental":{"fingerprints":["chrome"],"quic-go-disable-gso":true,"quic-go-disable-ecn":true,"dialer-ip4p-convert":true},"tunnels":[{"network":["tcp","udp"],"address":"127.0.0.1:5353","target":"192.0.2.1:53","proxy":"DIRECT"}]}`)
	var fromJSON, fromYAML RawConfig
	if err := json.Unmarshal(input, &fromJSON); err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(input, &fromYAML); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fromJSON, fromYAML) {
		t.Errorf("JSON and YAML disagree: JSON tun=%+v experimental=%+v", fromJSON.Tun, fromJSON.Experimental)
	}
	encoded, err := json.Marshal(fromYAML)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	for section, keys := range map[string][]string{"tun": {"auto-detect-interface"}, "experimental": {"fingerprints", "quic-go-disable-gso", "quic-go-disable-ecn", "dialer-ip4p-convert"}} {
		var values map[string]any
		if err := json.Unmarshal(fields[section], &values); err != nil {
			t.Fatal(err)
		}
		for _, key := range keys {
			if _, ok := values[key]; !ok {
				t.Errorf("missing JSON field %s.%s", section, key)
			}
		}
	}
	var tunnels []map[string]any
	if err := json.Unmarshal(fields["tunnels"], &tunnels); err != nil {
		t.Fatal(err)
	}
	if len(tunnels) != 1 {
		t.Fatalf("tunnels=%v", tunnels)
	}
	for _, key := range []string{"network", "address", "target", "proxy"} {
		if _, ok := tunnels[0][key]; !ok {
			t.Errorf("missing tunnel JSON field %s", key)
		}
	}
}
