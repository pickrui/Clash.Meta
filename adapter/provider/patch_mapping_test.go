package provider

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	agekey "github.com/metacubex/age"
	"github.com/metacubex/mihomo/component/age"
	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

func TestProxyMappingUsesEffectiveProviderSettings(t *testing.T) {
	payload := []map[string]any{
		{"name": "HK-01", "type": "ss", "server": "127.0.0.1", "port": 9, "cipher": "aes-128-gcm", "password": "fixture"},
		{"name": "US-01", "type": "direct"},
		{"name": "HK-blocked", "type": "direct"},
	}
	pd, err := ParseProxyProvider("fixture", map[string]any{
		"type": "inline", "payload": payload, "filter": "HK-", "exclude-filter": "blocked", "exclude-type": "direct",
		"dialer-proxy": "upstream", "override": map[string]any{"additional-prefix": "prefix-", "name-cert-verify": "cert.example", "skip-cert-verify": false},
	}, nil)
	require.NoError(t, err)
	defer pd.(*InlineProvider).Close()
	require.Len(t, pd.Proxies(), 1)
	name := pd.Proxies()[0].Name()
	require.Equal(t, "prefix-HK-01", name)
	for range 2 {
		mapping, err := ProxyMapping(pd, name)
		require.NoError(t, err)
		require.Equal(t, name, mapping["name"])
		require.Equal(t, "upstream", mapping["dialer-proxy"])
		require.Equal(t, "cert.example", mapping["name-cert-verify"])
		require.Equal(t, false, mapping["skip-cert-verify"])
		require.Equal(t, "fixture", mapping["password"])
	}
	for _, missing := range []string{"HK-01", "prefix-US-01", "prefix-HK-blocked"} {
		mapping, err := ProxyMapping(pd, missing)
		require.NoError(t, err)
		require.Nil(t, mapping)
	}
	require.Equal(t, "HK-01", payload[0]["name"])
}

func TestProxyMappingReadsOnlyCurrentBoundedAgeSnapshot(t *testing.T) {
	previous := C.Path.HomeDir()
	C.SetHomeDir(t.TempDir())
	t.Cleanup(func() { C.SetHomeDir(previous) })
	key, err := agekey.GenerateX25519Identity()
	require.NoError(t, err)
	content, err := age.EncryptBytes([]byte("proxies: [{name: fixture, type: direct}]"), key.Recipient().String())
	require.NoError(t, err)
	path := filepath.Join(C.Path.HomeDir(), "provider.yaml")
	require.NoError(t, os.WriteFile(path, content, 0600))
	pd, err := ParseProxyProvider("fixture", map[string]any{"type": "file", "path": path, "age-secret-key": key.String()}, nil)
	require.NoError(t, err)
	defer pd.(*ProxySetProvider).Close()
	require.NoError(t, pd.Initial())
	mapping, err := ProxyMapping(pd, "fixture")
	require.NoError(t, err)
	require.Equal(t, "fixture", mapping["name"])
	require.NotContains(t, mapping, "age-secret-key")
	require.NoError(t, os.WriteFile(path, []byte("proxies: [{name: fixture, type: reject}]"), 0600))
	_, err = ProxyMapping(pd, "fixture")
	require.Error(t, err)
	require.NoError(t, os.Truncate(path, maxMappingBytes+1))
	_, err = ProxyMapping(pd, "fixture")
	require.Error(t, err)
}

func TestProxyMappingKeepsRegexTimeout(t *testing.T) {
	pd, err := ParseProxyProvider("fixture", map[string]any{"type": "inline", "payload": []map[string]any{{"name": strings.Repeat("a", 512) + "!", "type": "direct"}}}, nil)
	require.NoError(t, err)
	defer pd.(*InlineProvider).Close()
	pd.(*InlineProvider).mappingSchema.Filter = "^(a+)+$"
	_, err = ProxyMapping(pd, "missing")
	require.ErrorContains(t, err, "timeout")
}
