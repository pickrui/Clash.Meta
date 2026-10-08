//go:build !no_zerotier

package outbound

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	ZT "github.com/metacubex/zerotier-go"
	ZTTransport "github.com/metacubex/zerotier-go/transport"
)

func TestZeroTierConfiguredIdentity(t *testing.T) {
	previousHome := C.Path.HomeDir()
	C.SetHomeDir(t.TempDir())
	t.Cleanup(func() { C.SetHomeDir(previousHome) })
	identity, err := ZT.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, secret string
		valid        bool
	}{
		{"default", "", true},
		{"private", identity.SecretString(), true},
		{"public only", identity.PublicString(), false},
		{"malformed", "fixture-private-secret", false},
		{"mismatched private key", identity.PublicString() + ":" + strings.Repeat("00", 64), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			outbound, err := NewZeroTier(ZeroTierOption{Name: "fixture", Network: "8056c2e21c000001", IdentitySecret: tc.secret})
			if !tc.valid {
				if err == nil {
					_ = outbound.Close()
					t.Fatal("invalid identity accepted")
				}
				if strings.Contains(err.Error(), tc.secret) {
					t.Fatal("error disclosed secret identity")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer outbound.Close()
			if tc.secret == "" {
				if !outbound.configuredIdentity.Address().IsZero() {
					t.Fatal("default identity behavior changed")
				}
				return
			}
			if outbound.configuredIdentity.SecretString() != identity.SecretString() {
				t.Fatal("configured identity changed")
			}

			store := ZT.NewMemoryStore()
			if err := store.Put("identity.secret", []byte(identity.SecretString())); err != nil {
				t.Fatal(err)
			}
			wire, err := ZTTransport.New(ZTTransport.Config{Dialer: zeroTierOfflineDialer{}})
			if err != nil {
				t.Fatal(err)
			}
			node, err := ZT.NewNode(ZT.NodeConfig{Identity: identity, Store: store, Sender: wire})
			if err != nil {
				_ = wire.Close()
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			runtime := &zeroTierRuntime{node: node, nodeAddress: identity.Address(), wire: wire, ctx: ctx, cancel: cancel}
			outbound.stateStore, outbound.runtime = store, runtime
			before, err := store.Get("identity.secret")
			if err != nil {
				t.Fatal(err)
			}
			outbound.recoverIdentityCollision(nil, identity.Address())
			if outbound.runtime != runtime {
				t.Fatal("stale callback retired the current runtime")
			}
			outbound.recoverIdentityCollision(runtime, identity.Address())
			if outbound.runtime != nil || !errors.Is(outbound.networkErr, ZT.ErrIdentityCollision) || ctx.Err() == nil {
				t.Fatal("collision did not retire the runtime and report an error")
			}
			after, err := store.Get("identity.secret")
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("configured identity was rotated or removed")
			}
			if _, err := store.Get("identity.secret.saved_after_collision"); !errors.Is(err, ZT.ErrStateNotFound) {
				t.Fatalf("configured identity unexpectedly rotated: %v", err)
			}
			if remaining := time.Until(outbound.identityCollisionRetryAt); remaining <= 0 || remaining > zeroTierIdentityCollisionRetryInterval {
				t.Fatalf("collision cooldown = %v", remaining)
			}
			if err := outbound.start(); !errors.Is(err, ZT.ErrIdentityCollision) || outbound.runtime != nil {
				t.Fatalf("cooldown attempted restart: %v", err)
			}
		})
	}
}

type zeroTierOfflineDialer struct{}

func (zeroTierOfflineDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("network disabled in identity fixture")
}
func (zeroTierOfflineDialer) ListenPacket(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
	return nil, errors.New("network disabled in identity fixture")
}
