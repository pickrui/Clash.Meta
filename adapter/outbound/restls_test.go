package outbound

import (
	"strings"
	"testing"

	"github.com/metacubex/mihomo/common/structure"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/restls"
)

func decodeRestlsProxy(t *testing.T, protocol string, input map[string]any) (C.ProxyAdapter, *restls.Config, error) {
	t.Helper()
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
	switch protocol {
	case "vmess":
		var o VmessOption
		if err := decoder.Decode(input, &o); err != nil {
			t.Fatal(err)
		}
		p, err := NewVmess(o)
		if err != nil {
			return nil, nil, err
		}
		return p, p.restlsConfig, nil
	case "vless":
		var o VlessOption
		if err := decoder.Decode(input, &o); err != nil {
			t.Fatal(err)
		}
		p, err := NewVless(o)
		if err != nil {
			return nil, nil, err
		}
		return p, p.restlsConfig, nil
	default:
		var o TrojanOption
		if err := decoder.Decode(input, &o); err != nil {
			t.Fatal(err)
		}
		p, err := NewTrojan(o)
		if err != nil {
			return nil, nil, err
		}
		return p, p.restlsConfig, nil
	}
}

func TestProtocolRestlsConfiguration(t *testing.T) {
	for _, protocol := range []string{"vmess", "vless", "trojan"} {
		for _, scenario := range []string{"valid", "disabled", "bad_script", "bad_version", "missing_tls", "reality", "ech", "client_certificate"} {
			t.Run(protocol+"/"+scenario, func(t *testing.T) {
				opts := map[string]any{"password": "test-password", "version-hint": "tls13", "restls-script": "1500"}
				input := map[string]any{"name": "test", "server": "127.0.0.1", "port": 443, "uuid": "d342d11e-d424-4583-b36e-524ab1f0afa4", "alterId": 0, "cipher": "auto", "password": "trojan-password", "tls": true, "servername": "camouflage.test", "sni": "camouflage.test", "client-fingerprint": "firefox", "restls-opts": opts}
				want := ""
				switch scenario {
				case "disabled":
					delete(input, "restls-opts")
				case "bad_script":
					opts["restls-script"] = "40000"
					want = "invalid"
				case "bad_version":
					opts["version-hint"] = "ssl3"
					want = "invalid version hint"
				case "missing_tls":
					input["tls"] = false
					if protocol != "trojan" {
						want = "requires TLS"
					}
				case "reality":
					input["reality-opts"] = map[string]any{"public-key": strings.Repeat("A", 43)}
					want = "incompatible with REALITY"
				case "ech":
					input["ech-opts"] = map[string]any{"enable": true}
					want = "does not support ECH"
				case "client_certificate":
					input["certificate"] = "client.pem"
					want = "does not support client certificates"
				}
				proxy, config, err := decodeRestlsProxy(t, protocol, input)
				if want != "" {
					if err == nil {
						proxy.Close()
						t.Fatal("unsupported configuration accepted")
					}
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("unexpected error: %v", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				defer proxy.Close()
				if scenario == "disabled" {
					if config != nil {
						t.Fatal("disabled Restls was enabled")
					}
					return
				}
				if config == nil || config.ServerName != "camouflage.test" || config.ClientID.Load().Client != "Firefox" || config.InsecureSkipVerify || config.Time == nil || config.ClientSessionCache == nil {
					t.Fatal("Restls options or TLS defaults were lost")
				}
			})
		}
	}
}

func TestVlessRestlsDownloadValidation(t *testing.T) {
	for _, scenario := range []string{"inherit", "override", "disable", "no_tls", "bad_script", "reality", "ech", "client_certificate"} {
		t.Run(scenario, func(t *testing.T) {
			ds := &XHTTPDownloadSettings{}
			option := VlessOption{Name: "test", Server: "127.0.0.1", Port: 443, UUID: "d342d11e-d424-4583-b36e-524ab1f0afa4", TLS: true, RestlsOpts: RestlsOptions{Password: "upload", VersionHint: "tls13"}, Network: "xhttp", XHTTPOpts: XHTTPOptions{Mode: "stream-up", DownloadSettings: ds}}
			want := ""
			switch scenario {
			case "override":
				ds.RestlsOpts = &RestlsOptions{Password: "download", VersionHint: "tls12"}
			case "disable":
				ds.RestlsOpts = &RestlsOptions{}
			case "no_tls":
				ds.TLS = new(bool)
				want = "Restls requires TLS"
			case "bad_script":
				ds.RestlsOpts = &RestlsOptions{Password: "download", VersionHint: "tls13", RestlsScript: "40000"}
				want = "invalid"
			case "reality":
				ds.RealityOpts = &RealityOptions{PublicKey: strings.Repeat("A", 43)}
				want = "incompatible with REALITY"
			case "ech":
				ds.ECHOpts = &ECHOptions{Enable: true}
				want = "does not support ECH"
			case "client_certificate":
				value := "client.pem"
				ds.Certificate = &value
				want = "does not support client certificates"
			}
			p, err := NewVless(option)
			if want != "" {
				if err == nil {
					p.Close()
					t.Fatal("invalid download settings accepted")
				}
				if !strings.Contains(err.Error(), "xhttp download-settings:") || !strings.Contains(err.Error(), want) {
					t.Fatal(err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			p.Close()
		})
	}
}

func TestVlessRestlsRejectsVision(t *testing.T) {
	p, err := NewVless(VlessOption{Name: "test", Server: "127.0.0.1", Port: 443, UUID: "d342d11e-d424-4583-b36e-524ab1f0afa4", TLS: true, Flow: "xtls-rprx-vision", RestlsOpts: RestlsOptions{Password: "test", VersionHint: "tls13"}})
	if err == nil {
		p.Close()
		t.Fatal("Restls cannot provide the outer TLS state required by Vision")
	}
	if !strings.Contains(err.Error(), "Restls does not support XTLS Vision") {
		t.Fatal(err)
	}
}
