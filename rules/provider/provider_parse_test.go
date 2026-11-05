package provider

import (
	"fmt"
	"slices"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

type parsedRuleStrings struct{ rules []string }

func (s *parsedRuleStrings) Behavior() P.RuleBehavior { return P.Domain }
func (s *parsedRuleStrings) Match(metadata *C.Metadata, _ C.RuleMatchHelper) bool {
	return slices.Contains(s.rules, metadata.Host)
}
func (s *parsedRuleStrings) Count() int         { return len(s.rules) }
func (s *parsedRuleStrings) Reset()             { s.rules = nil }
func (s *parsedRuleStrings) Insert(rule string) { s.rules = append(s.rules, rule) }
func (s *parsedRuleStrings) FinishInsert()      {}

func TestRulesParseYAMLDocument(t *testing.T) {
	tests := []struct {
		name, data, match string
		count             int
		invalid           bool
	}{
		{name: "block", data: "payload:\n  - 'example.com'\n", count: 1},
		{name: "block without final newline", data: "payload:\n- example.com", count: 1},
		{name: "flow", data: "payload: ['example.com']\n", count: 1},
		{name: "flow without final newline", data: "payload: ['example.com']", count: 1},
		{name: "rules alias", data: "rules: ['example.com']\n", count: 1},
		{name: "empty payload", data: "payload: []\n", count: 0},
		{name: "empty rules", data: "rules: []", count: 0},
		{name: "comments", data: "# rules\npayload: # domain rules\n  - 'example.com' # one\n", count: 1},
		{name: "extra fields", data: "name: sample\npayload:\n  - example.com\n", count: 1},
		{name: "document markers", data: "---\npayload:\n  - example.com\n...\n", count: 1},
		{name: "missing payload", data: "other: ['example.com']\n", invalid: true},
		{name: "empty file", data: "", invalid: true},
		{name: "null payload", data: "payload:\n", invalid: true},
		{name: "wrong type", data: "payload: example.com\n", invalid: true},
		{name: "malformed header", data: "payload: [\n", invalid: true},
		{name: "scalar continuation", data: "payload:\n  - example.com\n    - bad.example.com\n", count: 1, match: "example.com - bad.example.com"},
		{name: "inconsistent indentation", data: "payload:\n  - example.com\n - bad.example.com\n", invalid: true},
		{name: "malformed item", data: "payload:\n  - example.com\n  - [\n", invalid: true},
		{name: "invalid prefix", data: "broken: [\npayload:\n  - example.com\n", invalid: true},
		{name: "duplicate key", data: "payload:\n  - example.com\npayload: []\n", invalid: true},
		{name: "multiple documents", data: "payload:\n  - example.com\n---\npayload: []\n", invalid: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			strategy, err := rulesParse([]byte(test.data), &parsedRuleStrings{}, P.YamlRule)
			if test.invalid {
				if err == nil {
					t.Fatal("invalid YAML was accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if strategy.Count() != test.count {
				t.Fatalf("count = %d, want %d", strategy.Count(), test.count)
			}
			host := test.match
			if host == "" {
				host = "example.com"
			}
			if test.count > 0 && !strategy.Match(&C.Metadata{Host: host}, C.RuleMatchHelper{}) {
				t.Fatal("parsed rule does not match")
			}
		})
	}
}

func BenchmarkRulesParseBlockYAML(b *testing.B) {
	data := []byte("payload:\n")
	for index := range 10000 {
		data = fmt.Appendf(data, "  - '%d.example.com'\n", index)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	for b.Loop() {
		if _, err := rulesParse(data, NewDomainStrategy(), P.YamlRule); err != nil {
			b.Fatal(err)
		}
	}
}
