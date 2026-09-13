package restls

import (
	"crypto/x509"
	"fmt"
	"testing"

	tls "github.com/metacubex/restls-client-go"
	"github.com/stretchr/testify/require"
)

func TestClientNameCertVerify(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(fmt.Sprintf("%x", version), func(t *testing.T) {
			for _, scenario := range []string{"valid", "wrong name", "untrusted", "skip still checks name", "leaf pin precedence"} {
				t.Run(scenario, func(t *testing.T) {
					observed := make(chan string, 8)
					address, roots, pin := restlsTestPeer(t, version, func(sni string) { observed <- sni })
					hint := "tls13"
					if version == tls.VersionTLS12 {
						hint = "tls12"
					}
					config, err := NewRestlsConfig("front.test", "local-restls-password", hint, "", "chrome")
					require.NoError(t, err)
					config.RootCAs = roots
					config.ForceTLS12 = version == tls.VersionTLS12
					name := "restls.test"
					wantErr := false
					switch scenario {
					case "wrong name":
						name = "wrong.test"
						wantErr = true
					case "untrusted":
						config.RootCAs = x509.NewCertPool()
						wantErr = true
					case "skip still checks name":
						config.InsecureSkipVerify = true
						name = "wrong.test"
						wantErr = true
					}
					if scenario == "leaf pin precedence" {
						require.NoError(t, SetFingerprint(config, pin, "wrong.test"))
					} else {
						SetNameCertVerify(config, name)
					}
					state, err := restlsTestExchange(address, config)
					if wantErr {
						require.Error(t, err)
						return
					}
					require.NoError(t, err)
					require.Equal(t, "front.test", <-observed)
					if scenario == "valid" && version == tls.VersionTLS12 {
						state, err = restlsTestExchange(address, config)
						require.NoError(t, err)
						require.True(t, state.DidResume)
						SetNameCertVerify(config, "wrong.test")
						_, err = restlsTestExchange(address, config)
						require.Error(t, err)
					}
				})
			}
		})
	}
}
