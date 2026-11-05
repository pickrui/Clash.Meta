//go:build !with_gvisor || no_tailscale

package outbound

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

type Tailscale struct {
	*Base
}

type TailscaleOption struct {
	BasicOption
	Name       string `proxy:"name"`
	Hostname   string `proxy:"hostname,omitempty"`
	AuthKey    string `proxy:"auth-key,omitempty"`
	ControlURL string `proxy:"control-url,omitempty"`
	StateDir   string `proxy:"state-dir,omitempty"`
	Ephemeral  bool   `proxy:"ephemeral,omitempty"`
	UDP        bool   `proxy:"udp,omitempty"`

	AcceptRoutes           *bool  `proxy:"accept-routes,omitempty"`
	ExitNode               string `proxy:"exit-node,omitempty"`
	ExitNodeAllowLANAccess *bool  `proxy:"exit-node-allow-lan-access,omitempty"`
}

var errTailscaleDisabled = fmt.Errorf("tailscale support is disabled by \"no_tailscale\" build tag or not include \"with_gvisor\" build tag")

func NewTailscale(option TailscaleOption) (*Tailscale, error) {
	return nil, errTailscaleDisabled
}

func (t *Tailscale) Warm() {}

func (t *Tailscale) Login(ctx context.Context, authKey string) error {
	return errTailscaleDisabled
}

func (t *Tailscale) Logout(ctx context.Context) error {
	return errTailscaleDisabled
}

func (t *Tailscale) Status(ctx context.Context) (*TailscaleStatus, error) {
	return nil, errTailscaleDisabled
}

func (t *Tailscale) HasExitNode() bool {
	return false
}

func (t *Tailscale) PingPeers(ctx context.Context) (time.Duration, error) {
	return 0, errTailscaleDisabled
}

func ForgetTailscaleState(stateDir string) error {
	if strings.TrimSpace(stateDir) == "" {
		return errors.New("missing tailscale state-dir")
	}
	resolved := filepath.Clean(C.Path.Resolve(stateDir))
	if !C.Path.IsSafePath(resolved) {
		return C.Path.ErrNotSafePath(resolved)
	}
	return os.RemoveAll(resolved)
}
