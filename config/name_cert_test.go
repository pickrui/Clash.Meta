package config

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestDNSNameCertVerifyParameter(t *testing.T) {
	for _, scheme := range []string{"tls", "https", "quic"} {
		for _, name := range []string{"certificate.test", ""} {
			t.Run(scheme+"/"+name, func(t *testing.T) {
				servers, err := parseNameServer([]string{scheme + "://front.test:853#name-cert-verify=" + name + "&skip-cert-verify=false"}, false, false)
				require.NoError(t, err)
				require.Len(t, servers, 1)
				require.Equal(t, name, servers[0].Params["name-cert-verify"])
				require.Equal(t, "false", servers[0].Params["skip-cert-verify"])
				require.Contains(t, servers[0].Addr, "front.test:853")
			})
		}
	}
}
