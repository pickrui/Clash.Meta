package outbound

import (
	"testing"

	"github.com/metacubex/mihomo/component/ca"
)

func tuicMemoryOption(token string) TuicOption {
	return TuicOption{
		Name: "fixture", Server: "127.0.0.1", Port: 443, SNI: "proxy.test", Token: token,
		UUID: "9f3fe162-0d26-475b-9f8c-7f121923206a", Password: "fixture",
	}
}

func BenchmarkTuicConstruction(b *testing.B) {
	ca.GetCertPool()
	for _, version := range []string{"v4", "v5"} {
		b.Run(version, func(b *testing.B) {
			token := ""
			if version == "v4" {
				token = "fixture-token"
			}
			option := tuicMemoryOption(token)
			b.ReportAllocs()
			for b.Loop() {
				node, err := NewTuic(option)
				if err != nil {
					b.Fatal(err)
				}
				_ = node.Close()
			}
		})
	}
}
