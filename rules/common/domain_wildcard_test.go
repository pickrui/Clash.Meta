package common

import (
	C "github.com/metacubex/mihomo/constant"
	"testing"
)

func TestDomainWildcardUsesRuleHost(t *testing.T) {
	rule, err := NewDomainWildcard("*.example.test", "PROXY")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		host, sniff string
		want        bool
	}{
		{"www.example.test", "", true},
		{"", "www.example.test", true},
		{"other.test", "www.example.test", true},
		{"www.example.test", "other.test", false},
		{"", "", false},
	} {
		got, _ := rule.Match(&C.Metadata{Host: tc.host, SniffHost: tc.sniff}, C.RuleMatchHelper{})
		if got != tc.want {
			t.Errorf("host=%q sniff=%q got %t, want %t", tc.host, tc.sniff, got, tc.want)
		}
	}
}
