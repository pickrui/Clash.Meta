package outbound

import (
	"errors"

	C "github.com/metacubex/mihomo/constant"
)

// TailscaleIdle is reported while no session has been started for an outbound.
const TailscaleIdle = "Idle"

var (
	errTailscaleClosed     = errors.New("tailscale outbound closed")
	errTailscaleSuperseded = errors.New("tailscale state-dir is used by a newer outbound")
	errTailscaleRemoved    = errors.New("tailscale network was removed")
	errTailscaleRetired    = errors.New("tailscale session restarted")
	errTailscaleNotRunning = errors.New("tailscale network is not running")
)

// TailscaleStatus is the credential-free view of one outbound's session.
type TailscaleStatus struct {
	// State is an ipn.State name, or TailscaleIdle before the session starts.
	State          string            `json:"state"`
	AuthURL        string            `json:"authUrl,omitempty"`
	Error          string            `json:"error,omitempty"`
	Tailnet        string            `json:"tailnet,omitempty"`
	MagicDNSSuffix string            `json:"magicDnsSuffix,omitempty"`
	KeyExpired     bool              `json:"keyExpired,omitempty"`
	Health         []string          `json:"health,omitempty"`
	Self           *TailscaleDevice  `json:"self,omitempty"`
	Peers          []TailscaleDevice `json:"peers"`
}

type TailscaleDevice struct {
	Name           string   `json:"name"`
	HostName       string   `json:"hostName,omitempty"`
	OS             string   `json:"os,omitempty"`
	Addresses      []string `json:"addresses"`
	Online         bool     `json:"online"`
	Direct         bool     `json:"direct,omitempty"`
	Relay          string   `json:"relay,omitempty"`
	ExitNodeOption bool     `json:"exitNodeOption,omitempty"`
	ExitNode       bool     `json:"exitNode,omitempty"`
}

// AsTailscale returns the Tailscale outbound behind a parsed proxy.
func AsTailscale(proxy C.Proxy) (*Tailscale, bool) {
	if proxy == nil {
		return nil, false
	}
	adapter := proxy.Adapter()
	if wrapper, ok := adapter.(*autoCloseProxyAdapter); ok {
		adapter = wrapper.ProxyAdapter
	}
	tailscale, ok := adapter.(*Tailscale)
	return tailscale, ok
}
