package common

import (
	"github.com/metacubex/mihomo/component/tailnet"
	C "github.com/metacubex/mihomo/constant"
)

// Tailnet matches the peers, MagicDNS names and approved subnets a Tailscale
// outbound currently knows, following its network map as devices join and
// leave. It classifies the address a connection already has and never resolves
// a hostname itself, so it cannot move DNS ahead of the profile's rules.
type Tailnet struct {
	Base
	network string
	adapter string
}

func (t *Tailnet) RuleType() C.RuleType {
	return C.Tailnet
}

func (t *Tailnet) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	routes := tailnet.Lookup(t.network)
	if routes == nil {
		return false, t.adapter
	}
	if routes.MatchHost(metadata.RuleHost()) {
		return true, t.adapter
	}
	return routes.MatchAddr(metadata.DstIP), t.adapter
}

func (t *Tailnet) Adapter() string {
	return t.adapter
}

func (t *Tailnet) Payload() string {
	return t.network
}

func NewTailnet(network string, adapter string) *Tailnet {
	return &Tailnet{
		network: network,
		adapter: adapter,
	}
}

var _ C.Rule = (*Tailnet)(nil)
