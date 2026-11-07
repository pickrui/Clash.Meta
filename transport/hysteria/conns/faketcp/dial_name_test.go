package faketcp

import (
	"errors"
	"testing"

	"github.com/metacubex/mihomo/component/resolver"
)

func TestDialAsksTheResolverPackageFirst(t *testing.T) {
	previous := resolver.LookupGuard
	t.Cleanup(func() { resolver.LookupGuard = previous })
	refusal := errors.New("refused")
	resolver.LookupGuard = func(host string, _ resolver.Resolver) error {
		if host == "refused.example" {
			return refusal
		}
		return nil
	}
	if err := checkDialName("refused.example:443"); !errors.Is(err, refusal) {
		t.Fatalf("a refused name = %v", err)
	}
	for _, address := range []string{"public.example:443", "192.0.2.1:443", "not an address"} {
		if err := checkDialName(address); err != nil {
			t.Fatalf("%q = %v", address, err)
		}
	}
	resolver.LookupGuard = nil
	if err := checkDialName("refused.example:443"); err != nil {
		t.Fatalf("no guard refused a name: %v", err)
	}
}
