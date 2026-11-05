package outbound

import (
	"crypto/x509"
	"github.com/metacubex/mihomo/common/structure"
	"github.com/metacubex/mihomo/component/ech"
	"github.com/metacubex/mihomo/internal/testutil"
	"github.com/metacubex/tls"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSnellNameCertVerifyOptions(t *testing.T) {
	cert := testutil.NewCertificate(t, "certificate.test")
	echConfig, _, err := ech.GenECHConfig("public.test")
	require.NoError(t, err)
	proxy, err := NewSnell(SnellOption{Name: "snell", Server: "127.0.0.1", Port: 443, Psk: "test", Version: 4, ObfsOpts: map[string]any{"mode": "ech-tls", "sni": "front.test", "ech-config": echConfig, "ca-file": cert.RootPEM, "name-cert-verify": "certificate.test"}})
	require.NoError(t, err)
	defer proxy.Close()
	require.Equal(t, "certificate.test", proxy.echTLS.NameCertVerify)
	config, err := proxy.echTLS.ToStdConfig()
	require.NoError(t, err)
	require.Equal(t, "front.test", config.ServerName)
	require.NoError(t, config.VerifyConnection(tls.ConnectionState{ServerName: "front.test", PeerCertificates: []*x509.Certificate{cert.Leaf, cert.Root}}))
	require.NotNil(t, proxy.echTLS.ClientSessionCache)
	require.NotNil(t, proxy.echTLS.UClientSessionCache)
	var option SnellOption
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true})
	require.NoError(t, decoder.Decode(map[string]any{"name": "snell", "server": "127.0.0.1", "port": 443, "psk": "test", "version": 4, "shadow-tls-password": "test", "shadow-tls-sni": "front.test", "shadow-tls-name-cert-verify": "certificate.test"}, &option))
	shadow, err := snellShadowTLSOption(option)
	require.NoError(t, err)
	require.Equal(t, "certificate.test", shadow.NameCertVerify)
	require.Equal(t, "front.test", shadow.Host)
	_, err = snellShadowTLSOption(SnellOption{ShadowTLSNameCertVerify: "certificate.test"})
	require.Error(t, err)
}
