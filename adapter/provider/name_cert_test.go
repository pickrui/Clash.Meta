package provider

import (
	"github.com/metacubex/mihomo/common/structure"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestOverrideNameCertVerify(t *testing.T) {
	for _, scenario := range []string{"inherit", "replace", "clear"} {
		t.Run(scenario, func(t *testing.T) {
			input := map[string]any{}
			want := "original.test"
			if scenario == "replace" {
				want = "override.test"
				input["name-cert-verify"] = want
			}
			if scenario == "clear" {
				want = ""
				input["name-cert-verify"] = ""
			}
			var override overrideSchema
			decoder := structure.NewDecoder(structure.Option{TagName: "provider", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
			require.NoError(t, decoder.Decode(input, &override))
			proxy := map[string]any{"name": "proxy", "servername": "front.test", "name-cert-verify": "original.test", "skip-cert-verify": false}
			require.NoError(t, override.Apply(proxy))
			require.Equal(t, want, proxy["name-cert-verify"])
			require.Equal(t, "front.test", proxy["servername"])
			require.Equal(t, false, proxy["skip-cert-verify"])
		})
	}
}
