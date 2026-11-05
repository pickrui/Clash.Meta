package listener

import (
	"net"
	"strconv"
	"sync"
	"testing"

	A "github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"
	AT "github.com/metacubex/mihomo/listener/anytls"
	LC "github.com/metacubex/mihomo/listener/config"
	IN "github.com/metacubex/mihomo/listener/inbound"
	VL "github.com/metacubex/mihomo/listener/sing_vless"
	VM "github.com/metacubex/mihomo/listener/sing_vmess"
	TR "github.com/metacubex/mihomo/listener/trojan"
)

type restlsIdleTunnel struct{ C.Tunnel }

func newProtocolListener(kind, addr string, r LC.ResTLS) (C.MultiAddrListener, error) {
	tunnel := &restlsIdleTunnel{}
	addition := A.WithInName("restls-lifecycle")
	switch kind {
	case "anytls":
		return AT.New(LC.AnyTLSServer{Listen: addr, ResTLS: r, AllowInsecure: true}, A.NewListenConfig(), tunnel, addition)
	case "vmess":
		return VM.New(LC.VmessServer{Listen: addr, ResTLS: r}, A.NewListenConfig(), tunnel, addition)
	case "vless":
		return VL.New(LC.VlessServer{Listen: addr, ResTLS: r, AllowInsecure: true}, A.NewListenConfig(), tunnel, addition)
	default:
		return TR.New(LC.TrojanServer{Listen: addr, ResTLS: r, AllowInsecure: true}, A.NewListenConfig(), tunnel, addition)
	}
}

func protocolRestlsMapping(kind string, port int) map[string]any {
	mapping := map[string]any{"type": kind, "name": "restls-test", "listen": "127.0.0.1", "port": port, "allow-insecure": true, "users": []any{}, "res-tls": map[string]any{"enable": true, "dest": "camouflage.test:443", "password": "password", "min-record-len": 32, "rate-limit": 32768, "proxy": "route"}}
	if kind == "anytls" {
		mapping["users"] = map[string]string{}
	}
	return mapping
}

func TestProtocolRestlsListenerParsing(t *testing.T) {
	for _, kind := range []string{"vmess", "vless", "trojan", "anytls"} {
		t.Run(kind, func(t *testing.T) {
			mapping := protocolRestlsMapping(kind, 0)
			l, err := ParseListener(mapping)
			if err != nil {
				t.Fatal(err)
			}
			if err := l.Close(); err != nil {
				t.Fatal(err)
			}
			var r IN.ResTLS
			switch config := l.Config().(type) {
			case *IN.AnyTLSOption:
				r = config.ResTLS
			case *IN.VmessOption:
				r = config.ResTLS
			case *IN.VlessOption:
				r = config.ResTLS
			case *IN.TrojanOption:
				r = config.ResTLS
			default:
				t.Fatal("unexpected listener type")
			}
			want := LC.ResTLS{Enable: true, Dest: "camouflage.test:443", Password: "password", MinRecordLen: 32, RateLimit: 32768, Proxy: "route"}
			if r.Build() != want {
				t.Fatal("Restls options lost during listener parsing")
			}
			mapping["res-tls"].(map[string]any)["rate-limit"] = 65536
			changed, err := ParseListener(mapping)
			if err != nil {
				t.Fatal(err)
			}
			defer changed.Close()
			if l.Config().Equal(changed.Config()) {
				t.Fatal("Restls update did not trigger listener reload")
			}
			mapping["res-tls"].(map[string]any)["restls-script"] = "40000"
			if _, err := ParseListener(mapping); err == nil {
				t.Fatal("invalid Restls script accepted")
			}
		})
	}
}

func TestProtocolRestlsPartialBindRollback(t *testing.T) {
	for _, kind := range []string{"vmess", "vless", "trojan", "anytls"} {
		for _, enabled := range []bool{false, true} {
			t.Run(kind+"/restls="+strconv.FormatBool(enabled), func(t *testing.T) {
				first, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				blocked, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					first.Close()
					t.Fatal(err)
				}
				defer blocked.Close()
				address := first.Addr().String()
				first.Close()
				_, err = newProtocolListener(kind, address+","+blocked.Addr().String(), LC.ResTLS{Enable: enabled, Dest: "camouflage.test", Password: "password"})
				if err == nil {
					t.Fatal("occupied second address accepted")
				}
				rebound, err := net.Listen("tcp", address)
				if err != nil {
					t.Fatalf("first listener leaked: %v", err)
				}
				rebound.Close()
			})
		}
	}
}

func TestProtocolRestlsConcurrentClose(t *testing.T) {
	for _, kind := range []string{"vmess", "vless", "trojan", "anytls"} {
		t.Run(kind, func(t *testing.T) {
			l, err := newProtocolListener(kind, "127.0.0.1:0", LC.ResTLS{Enable: true, Dest: "camouflage.test", Password: "password"})
			if err != nil {
				t.Fatal(err)
			}
			address := l.AddrList()[0].String()
			var wg sync.WaitGroup
			for range 12 {
				wg.Go(func() {
					if err := l.Close(); err != nil {
						t.Error(err)
					}
				})
			}
			wg.Wait()
			rebound, err := net.Listen("tcp", address)
			if err != nil {
				t.Fatal(err)
			}
			rebound.Close()
		})
	}
}

func TestProtocolRestlsCloseAfterFailedListen(t *testing.T) {
	for _, kind := range []string{"vmess", "vless", "trojan", "anytls"} {
		t.Run(kind, func(t *testing.T) {
			blocked, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer blocked.Close()
			l, err := ParseListener(protocolRestlsMapping(kind, blocked.Addr().(*net.TCPAddr).Port))
			if err != nil {
				t.Fatal(err)
			}
			if err := l.Listen(&restlsIdleTunnel{}); err == nil {
				t.Fatal("occupied port accepted")
			}
			if err := l.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
