package route

import (
	"encoding/json"
	"fmt"
	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"strings"
	"testing"

	LC "github.com/metacubex/mihomo/listener/config"
)

func TestTunProcessorsPerChannelPatch(t *testing.T) {
	before := LC.Tun{ProcessorsPerChannel: 2}
	for _, tc := range []struct {
		body string
		want int
	}{
		{`{}`, 2},
		{`{"processors-per-channel":0}`, 0},
		{`{"processors-per-channel":4}`, 4},
	} {
		var patch tunSchema
		if err := json.Unmarshal([]byte(tc.body), &patch); err != nil {
			t.Fatal(err)
		}
		if got := pointerOrDefaultTun(&patch, before); got.ProcessorsPerChannel != tc.want {
			t.Fatalf("patch %s: processor count = %d, want %d", tc.body, got.ProcessorsPerChannel, tc.want)
		}
	}
	for _, count := range []int{-1, 257} {
		request := httptest.NewRequest(http.MethodPatch, "/configs", strings.NewReader(
			fmt.Sprintf(`{"tun":{"processors-per-channel":%d}}`, count),
		))
		response := httptest.NewRecorder()
		patchConfigs(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("unsafe processor count accepted: %d", response.Code)
		}
	}
}

func TestTunDNSModePatch(t *testing.T) {
	before := LC.Tun{DNSMode: "native"}
	if got := pointerOrDefaultTun(&tunSchema{}, before); got.DNSMode != "native" {
		t.Fatal("omitted mode changed the active configuration")
	}
	empty := ""
	if got := pointerOrDefaultTun(&tunSchema{DNSMode: &empty}, before); got.DNSMode != "" {
		t.Fatal("explicit empty mode did not restore legacy behavior")
	}
	request := httptest.NewRequest(http.MethodPatch, "/configs", strings.NewReader(`{"tun":{"dns-mode":"invalid"}}`))
	response := httptest.NewRecorder()
	patchConfigs(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid mode accepted: %d", response.Code)
	}
}
