package listener

import (
	"net"
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"
)

func TestStopListenerReleasesCustomInboundAndRestarts(t *testing.T) {
	inboundMux.Lock()
	previous := inboundListeners
	inboundListeners = map[string]C.InboundListener{}
	inboundMux.Unlock()
	t.Cleanup(func() {
		inboundMux.Lock()
		defer inboundMux.Unlock()
		for _, listener := range inboundListeners {
			_ = listener.Close()
		}
		inboundListeners = previous
	})
	options := inbound.BaseOption{NameStr: "stop-custom-regression", Listen: "127.0.0.1", Port: "0"}
	for name, create := range map[string]func() (C.InboundListener, error){
		"socks": func() (C.InboundListener, error) { return inbound.NewSocks(&inbound.SocksOption{BaseOption: options}) },
		"http":  func() (C.InboundListener, error) { return inbound.NewHTTP(&inbound.HTTPOption{BaseOption: options}) },
		"mixed": func() (C.InboundListener, error) { return inbound.NewMixed(&inbound.MixedOption{BaseOption: options}) },
		"sudoku": func() (C.InboundListener, error) {
			return inbound.NewSudoku(&inbound.SudokuOption{BaseOption: options, Key: "restart-fixture"})
		},
		"tunnel": func() (C.InboundListener, error) {
			return inbound.NewTunnel(&inbound.TunnelOption{BaseOption: options, Network: []string{"tcp"}, Target: "127.0.0.1:9"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			custom, err := create()
			if err != nil {
				t.Fatal(err)
			}
			defer StopListener()
			for round := 0; round < 2; round++ {
				PatchInboundListeners(map[string]C.InboundListener{custom.Name(): custom}, nil, true)
				address := strings.TrimPrefix(custom.Address(), "tcp://")
				if _, _, err := net.SplitHostPort(address); err != nil {
					t.Fatalf("restarting unchanged configuration retained retired endpoints: %q (%v)", address, err)
				}
				if probe, err := net.Listen("tcp", address); err == nil {
					_ = probe.Close()
					t.Fatalf("custom listener did not bind %s", address)
				}
				StopListener()
				probe, err := net.Listen("tcp", address)
				if err != nil {
					t.Fatalf("stop left custom inbound bound at %s: %v", address, err)
				}
				_ = probe.Close()
				StopListener()
			}
		})
	}
}
