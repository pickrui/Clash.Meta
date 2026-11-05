package outbound

import (
	"bytes"
	"encoding/base64"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

type nodeDNSFactory struct {
	name string
	new  func([]string) (C.ProxyAdapter, error)
}

func nodeDNSFactories(t testing.TB) []nodeDNSFactory {
	masque := masqueTestOption(t)
	masque.RemoteDnsResolve = true
	wireguard := WireGuardOption{
		Name: "dns-test", Ip: "10.0.0.1", Workers: 1, RemoteDnsResolve: true,
		PrivateKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
		WireGuardPeerOption: WireGuardPeerOption{
			Server: "127.0.0.1", Port: 51820,
			PublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)),
		},
	}
	return []nodeDNSFactory{
		{"wireguard", func(servers []string) (C.ProxyAdapter, error) {
			option := wireguard
			option.Dns = servers
			return NewWireGuard(option)
		}},
		{"masque", func(servers []string) (C.ProxyAdapter, error) {
			option := masque
			option.Dns = servers
			return NewMasque(option)
		}},
		{"masque-l4", func(servers []string) (C.ProxyAdapter, error) {
			option := masque
			option.Dns, option.Network = servers, "h3-l4proxy"
			return NewMasque(option)
		}},
	}
}

func BenchmarkUnusedNodeDNS(b *testing.B) {
	servers := []string{"192.0.2.53"}
	for _, factory := range nodeDNSFactories(b) {
		b.Run(factory.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				node, err := factory.new(servers)
				if err != nil {
					b.Fatal(err)
				}
				if err := node.Close(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
