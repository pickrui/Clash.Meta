package outbound

import (
	"github.com/metacubex/mihomo/common/structure"
	"strings"
	"testing"
)

func TestAnyTLSOptions(t *testing.T) {
	for _, scenario := range []string{"valid", "ordinary_tls", "bad_version", "bad_script", "ech", "certificate", "private_key"} {
		t.Run(scenario, func(t *testing.T) {
			input := map[string]any{"name": "test", "server": "127.0.0.1", "port": 443, "password": "test", "disable-reuse": true, "client-metadata": "custom-client/1", "restls-opts": map[string]any{"password": "restls", "version-hint": "tls13"}}
			want := ""
			switch scenario {
			case "ordinary_tls":
				delete(input, "restls-opts")
			case "bad_version":
				input["restls-opts"].(map[string]any)["version-hint"] = "ssl3"
				want = "invalid version hint"
			case "bad_script":
				input["restls-opts"].(map[string]any)["restls-script"] = "40000"
				want = "invalid"
			case "ech":
				input["ech-opts"] = map[string]any{"enable": true}
				want = "does not support ECH"
			case "certificate":
				input["certificate"] = "missing.pem"
				want = "does not support client certificates"
			case "private_key":
				input["private-key"] = "missing.key"
				want = "does not support client certificates"
			}
			var option AnyTLSOption
			decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
			if err := decoder.Decode(input, &option); err != nil {
				t.Fatal(err)
			}
			p, err := NewAnyTLS(option)
			if want != "" {
				if err == nil {
					p.Close()
					t.Fatal("invalid configuration accepted")
				}
				if !strings.Contains(err.Error(), want) {
					t.Fatal(err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			if !p.option.DisableReuse || p.option.ClientMetadata != "custom-client/1" {
				t.Fatal("new options lost during decoding")
			}
		})
	}
}
