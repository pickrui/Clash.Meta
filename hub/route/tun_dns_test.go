package route

import (
	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"strings"
	"testing"

	LC "github.com/metacubex/mihomo/listener/config"
)

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
