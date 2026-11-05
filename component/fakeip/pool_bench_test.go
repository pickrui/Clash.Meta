package fakeip

import (
	"fmt"
	"net/netip"
	"runtime"
	"testing"
)

func BenchmarkPoolMemory(b *testing.B) {
	for _, size := range []int{1000, 4096} {
		hosts := make([]string, size)
		for i := range hosts {
			hosts[i] = fmt.Sprintf("host-%d.example", i)
		}
		options := Options{IPNet: netip.MustParsePrefix("198.18.0.0/16"), Size: size}
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				pool, err := New(options)
				if err != nil {
					b.Fatal(err)
				}
				for _, host := range hosts {
					pool.Lookup(host)
				}
				runtime.KeepAlive(pool)
			}
		})
		b.Run(fmt.Sprintf("%d/hit", size), func(b *testing.B) {
			pool, err := New(options)
			if err != nil {
				b.Fatal(err)
			}
			for _, host := range hosts {
				pool.Lookup(host)
			}
			b.ReportAllocs()
			for b.Loop() {
				pool.Lookup(hosts[0])
			}
		})
		b.Run(fmt.Sprintf("%d/churn", size), func(b *testing.B) {
			pool, err := New(options)
			if err != nil {
				b.Fatal(err)
			}
			for _, host := range hosts {
				pool.Lookup(host)
			}
			churnHosts := append(append([]string(nil), hosts...), "extra.example")
			i := size
			b.ReportAllocs()
			for b.Loop() {
				pool.Lookup(churnHosts[i])
				i = (i + 1) % len(churnHosts)
			}
		})
	}
}
