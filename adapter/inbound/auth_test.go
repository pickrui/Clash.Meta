package inbound

import (
	"net/netip"
	"sync"
	"testing"
)

func TestConcurrentSkipAuthReplacement(t *testing.T) {
	previous := SkipAuthPrefixes()
	t.Cleanup(func() { SetSkipAuthPrefixes(previous) })
	var workers sync.WaitGroup
	for i := 0; i < 4; i++ {
		workers.Go(func() {
			for j := 0; j < 1000; j++ {
				SetSkipAuthPrefixes([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
				SkipAuthRemoteAddress("127.0.0.1:12345")
				SetSkipAuthPrefixes(nil)
			}
		})
	}
	workers.Wait()
}

func TestSkipAuthPrefixesOwnsItsSnapshot(t *testing.T) {
	previous := SkipAuthPrefixes()
	t.Cleanup(func() { SetSkipAuthPrefixes(previous) })
	prefixes := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	SetSkipAuthPrefixes(prefixes)
	prefixes[0] = netip.MustParsePrefix("10.0.0.0/8")
	returned := SkipAuthPrefixes()
	returned[0] = prefixes[0]
	if !SkipAuthRemoteAddress("127.0.0.1:12345") || SkipAuthRemoteAddress("10.0.0.1:12345") {
		t.Fatal("caller mutation changed the active auth policy")
	}
}
