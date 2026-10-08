package config

import "testing"

func TestEasyTierNameServerAliases(t *testing.T) {
	for _, server := range []string{"et://mesh", "easytier://mesh"} {
		parsed, err := parseNameServer([]string{server}, false, false)
		if err != nil || len(parsed) != 1 {
			t.Fatalf("parse %s: %v, %v", server, parsed, err)
		}
		if parsed[0].Net != "easytier" || parsed[0].Addr != "mesh" {
			t.Fatalf("%s resolved to %#v", server, parsed[0])
		}
	}
}
