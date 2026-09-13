package anytls

import (
	I "github.com/metacubex/mihomo/adapter/inbound"
	LC "github.com/metacubex/mihomo/listener/config"
	"strings"
	"testing"
)

func TestRestlsRejectsTLSOptions(t *testing.T) {
	for _, scenario := range []string{"certificate", "private_key", "client_auth", "client_auth_cert", "ech", "script", "destination"} {
		t.Run(scenario, func(t *testing.T) {
			c := LC.AnyTLSServer{Listen: "127.0.0.1:0", ResTLS: LC.ResTLS{Enable: true, Dest: "camouflage.test:443", Password: "restls"}}
			want := ""
			switch scenario {
			case "certificate":
				c.Certificate = "missing.pem"
				want = "certificate is unavailable"
			case "private_key":
				c.PrivateKey = "missing.key"
				want = "certificate is unavailable"
			case "client_auth":
				c.ClientAuthType = "require-and-verify"
				want = "client-auth is unavailable"
			case "client_auth_cert":
				c.ClientAuthCert = "missing.pem"
				want = "client-auth is unavailable"
			case "ech":
				c.EchKey = "invalid"
				want = "ECH is unavailable"
			case "script":
				c.ResTLS.RestlsScript = "40000"
				want = "invalid"
			case "destination":
				c.ResTLS.Dest = ""
				want = "dest"
			}
			l, err := New(c, I.NewListenConfig(), nil)
			if err == nil {
				l.Close()
				t.Fatal("invalid configuration accepted")
			}
			if !strings.Contains(err.Error(), want) {
				t.Fatal(err)
			}
		})
	}
}
