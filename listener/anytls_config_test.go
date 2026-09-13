package listener

import (
	"encoding/json"
	"testing"

	"github.com/metacubex/mihomo/listener/anytls"
	LC "github.com/metacubex/mihomo/listener/config"
	IN "github.com/metacubex/mihomo/listener/inbound"
)

func TestParseAnyTLSOptionalCertificateFields(t *testing.T) {
	for _, allow := range []bool{false, true} {
		listener, err := ParseListener(map[string]any{"name": "anytls-test", "type": "anytls", "listen": "127.0.0.1", "allow-insecure": allow, "users": map[string]string{"user": "fixture-password"}})
		if err != nil {
			t.Errorf("allow-insecure=%t: %v", allow, err)
			continue
		}
		option := listener.Config().(*IN.AnyTLSOption)
		if option.AllowInsecure != allow || option.Certificate != "" || option.PrivateKey != "" {
			t.Fatalf("unexpected config: %+v", option)
		}
	}
}

func TestAnyTLSStillRequiresExplicitInsecureOptIn(t *testing.T) {
	if listener, err := anytls.New(LC.AnyTLSServer{Listen: "127.0.0.1:0"}, nil); err == nil {
		_ = listener.Close()
		t.Fatal("missing certificates accepted without opt-in")
	}
}

func TestAnyTLSEmptyCertificatesOmittedFromJSON(t *testing.T) {
	encoded := LC.AnyTLSServer{AllowInsecure: true}.String()
	var fields map[string]any
	if err := json.Unmarshal([]byte(encoded), &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"certificate", "private-key"} {
		if _, exists := fields[key]; exists {
			t.Errorf("empty field %s retained", key)
		}
	}
}
