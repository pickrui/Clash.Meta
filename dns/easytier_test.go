package dns

import (
	"context"
	"errors"
	"testing"

	D "github.com/miekg/dns"
)

type meshDNSFixture struct {
	dnsClient
	err error
}

func (c meshDNSFixture) ExchangeContext(context.Context, *D.Msg) (*D.Msg, error) {
	return nil, c.err
}

func TestEasyTierDNSReplacementOwnership(t *testing.T) {
	first, second := errors.New("first instance"), errors.New("second instance")
	client := newEasyTierClient(t.Name())
	old := RegisterEasyTierDnsClient(t.Name(), meshDNSFixture{err: first})
	defer old()
	current := RegisterEasyTierDnsClient(t.Name(), meshDNSFixture{err: second})
	defer current()
	old()
	query := new(D.Msg).SetQuestion("fixture.easytier.", D.TypeA)
	if _, err := client.ExchangeContext(context.Background(), query); !errors.Is(err, second) {
		t.Fatalf("old instance removed the active resolver: %v", err)
	}
	current()
	if _, err := client.ExchangeContext(context.Background(), query); err == nil || errors.Is(err, second) {
		t.Fatalf("closed resolver remained registered: %v", err)
	}
}
