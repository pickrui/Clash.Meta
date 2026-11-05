package openvpn

import (
	"encoding/binary"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPeerInfoGeneratedFields(t *testing.T) {
	for _, tc := range []struct {
		name, comp, want string
		values           map[string]string
	}{
		{name: "version override and generated fields", comp: CompLzoYes, values: map[string]string{"IV_VER": "custom-client/1.0", "IV_PROTO": "999", "IV_CIPHERS": "unsupported", "IV_LZO": "0", "UV_ID": "id=001"}, want: "IV_VER=custom-client/1.0\nIV_PROTO=22\nIV_LZO=1\nIV_CIPHERS=AES-128-GCM\nUV_ID=id=001\n"},
		{name: "empty explicit version", values: map[string]string{"IV_VER": ""}, want: "IV_VER=\nIV_PROTO=22\nIV_CIPHERS=AES-128-GCM\n"},
		{name: "custom LZO without generated LZO", values: map[string]string{"IV_LZO": "0"}, want: "IV_VER=mihomo-openvpn\nIV_PROTO=22\nIV_CIPHERS=AES-128-GCM\nIV_LZO=0\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for range 10 {
				require.Equal(t, tc.want, InstallScriptPeerInfo(CipherAES128GCM, nil, tc.comp, tc.values))
			}
		})
	}
}

func TestPeerInfoRejectsInvalidEntries(t *testing.T) {
	for _, tc := range []struct{ name, key, value string }{
		{"empty key", "", "value"}, {"key equals", "UV_A=B", "value"},
		{"key newline", "UV_A\nIV_PROTO", "value"}, {"key return", "UV_A\rIV_PROTO", "value"}, {"key NUL", "UV_A\x00IV_PROTO", "value"},
		{"value newline", "UV_DEVICE_ID", "secret\nIV_PROTO=999"}, {"value return", "UV_DEVICE_ID", "secret\rIV_PROTO=999"}, {"value NUL", "UV_DEVICE_ID", "secret\x00IV_PROTO=999"},
		{"version injection", "IV_VER", "secret\nIV_CIPHERS=wrong"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := yamlStyleConfig()
			config.PeerInfo = map[string]string{tc.key: tc.value}
			err := config.Prepare()
			require.Error(t, err)
			if err != nil {
				require.NotContains(t, err.Error(), "secret")
			}
		})
	}
}

func TestPeerInfoLengthAndWireRoundTrip(t *testing.T) {
	overhead := len(InstallScriptPeerInfo(CipherAES128GCM, nil, "", map[string]string{"UV_DEVICE_ID": ""}))
	for _, size := range []int{0xfffe - 1, 0xfffe, 0xffff} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			config := yamlStyleConfig()
			config.PeerInfo = map[string]string{"UV_DEVICE_ID": strings.Repeat("x", size-overhead)}
			err := config.Prepare()
			if size > 0xfffe {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			peerInfo := InstallScriptPeerInfo(config.Cipher, config.DataCiphers, config.CompLZO, config.PeerInfo)
			require.Len(t, peerInfo, size)
			record, err := NewClientKeyMethod2Record("options", peerInfo, "user", "pass")
			require.NoError(t, err)
			encoded, err := record.MarshalClient()
			require.NoError(t, err)
			offset := 4 + 1 + keySourcePreMasterSize + 2*keySourceRandomSize
			for range 3 {
				_, offset, err = readOpenVPNString(encoded, offset)
				require.NoError(t, err)
			}
			require.Equal(t, uint16(size+1), binary.BigEndian.Uint16(encoded[offset:]))
			decoded, end, err := readOpenVPNString(encoded, offset)
			require.NoError(t, err)
			require.Equal(t, peerInfo, decoded)
			require.Equal(t, len(encoded), end)
		})
	}
}

func TestPeerInfoPrepareOwnsMetadata(t *testing.T) {
	values := map[string]string{"UV_DEVICE_ID": "before"}
	config := yamlStyleConfig()
	config.PeerInfo = values
	require.NoError(t, config.Prepare())
	values["UV_DEVICE_ID"] = "after\nIV_PROTO=999"
	require.Equal(t, "before", config.PeerInfo["UV_DEVICE_ID"])
}
