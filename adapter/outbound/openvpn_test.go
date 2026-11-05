package outbound

import (
	"strings"
	"testing"

	"github.com/metacubex/mihomo/common/structure"
	"github.com/metacubex/mihomo/component/ca"
	ovpn "github.com/metacubex/mihomo/transport/openvpn"
	"github.com/stretchr/testify/require"
)

func TestOpenVPNPeerInfoOptions(t *testing.T) {
	certificate, _, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	require.NoError(t, err)
	for _, scenario := range []string{"default", "metadata", "invalid key", "invalid value", "too long"} {
		t.Run(scenario, func(t *testing.T) {
			input := map[string]any{"name": "local-config", "server": "127.0.0.1", "port": 1194, "username": "test-user", "ca": certificate}
			fields := map[string]any{"IV_VER": "custom-client/1", "UV_DEVICE_ID": "id=001"}
			switch scenario {
			case "invalid key":
				fields["UV_BAD=KEY"] = "test"
			case "invalid value":
				fields["UV_DEVICE_ID"] = "private-value\nIV_PROTO=999"
			case "too long":
				fields["UV_DEVICE_ID"] = strings.Repeat("x", 65535)
			}
			if scenario != "default" {
				input["peer-info"] = fields
			}
			decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
			var option OpenVPNOption
			require.NoError(t, decoder.Decode(input, &option))
			proxy, err := NewOpenVPN(option)
			if scenario != "default" && scenario != "metadata" {
				if proxy != nil {
					_ = proxy.Close()
				}
				require.Error(t, err)
				if err != nil {
					require.NotContains(t, err.Error(), "private-value")
				}
				return
			}
			require.NoError(t, err)
			defer proxy.Close()
			want := "IV_VER=mihomo-openvpn\nIV_PROTO=22\nIV_CIPHERS=AES-128-GCM\n"
			if scenario == "metadata" {
				want = "IV_VER=custom-client/1\nIV_PROTO=22\nIV_CIPHERS=AES-128-GCM\nUV_DEVICE_ID=id=001\n"
				option.PeerInfo["UV_DEVICE_ID"] = "changed-after-construction"
			}
			require.Equal(t, want, ovpn.InstallScriptPeerInfo(proxy.config.Cipher, proxy.config.DataCiphers, proxy.config.CompLZO, proxy.config.PeerInfo))
			require.Nil(t, proxy.client) // Constructing metadata must not start a network connection or TUN.
			require.Nil(t, proxy.tunDevice)
		})
	}
}
