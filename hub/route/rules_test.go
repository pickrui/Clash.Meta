package route

import (
	"encoding/json"
	"testing"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

type payloadRule struct {
	constant.Rule
	payload string
}

func (r payloadRule) RuleType() constant.RuleType { return constant.DomainSuffix }
func (r payloadRule) Adapter() string             { return "DIRECT" }
func (r payloadRule) Payload() string             { return r.payload }

func TestRulesReportFilteredPayloads(t *testing.T) {
	previous := statistic.RulePayloadObfuscated
	t.Cleanup(func() {
		statistic.RulePayloadObfuscated = previous
		tunnel.UpdateRules(nil, nil, nil)
	})
	tunnel.UpdateRules([]constant.Rule{payloadRule{payload: "a.example"}, payloadRule{payload: "b.example"}}, nil, nil)
	payloads := func() []string {
		response := httptest.NewRecorder()
		getRules(response, httptest.NewRequest(http.MethodGet, "/rules", nil))
		var body struct {
			Rules []struct{ Payload string } `json:"rules"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		found := make([]string, 0, len(body.Rules))
		for _, rule := range body.Rules {
			found = append(found, rule.Payload)
		}
		return found
	}
	statistic.RulePayloadObfuscated = nil
	if got := payloads(); len(got) != 2 || got[0] != "a.example" || got[1] != "b.example" {
		t.Fatalf("without a filter = %v", got)
	}
	statistic.RulePayloadObfuscated = func(payload string) bool { return payload == "a.example" }
	if got := payloads(); len(got) != 2 || got[0] != "***" || got[1] != "b.example" {
		t.Fatalf("with a filter = %v", got)
	}
}
