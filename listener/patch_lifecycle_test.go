package listener

import (
	"net"
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/inbound"
	LT "github.com/metacubex/mihomo/listener/tunnel"
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

func TestStopListenerReleasesTunnelEndpoints(t *testing.T) {
	tunnelMux.Lock()
	previousTCP, previousUDP := tunnelTCPListeners, tunnelUDPListeners
	tunnelTCPListeners = map[string]*LT.Listener{}
	tunnelUDPListeners = map[string]*LT.PacketConn{}
	tunnelMux.Unlock()
	t.Cleanup(func() {
		PatchTunnel(nil, nil)
		tunnelMux.Lock()
		tunnelTCPListeners, tunnelUDPListeners = previousTCP, previousUDP
		tunnelMux.Unlock()
	})
	for round := 0; round < 2; round++ {
		PatchTunnel([]LC.Tunnel{{Network: []string{"tcp", "udp"}, Address: "127.0.0.1:0", Target: "127.0.0.1:80"}}, nil)
		var tcpAddress, udpAddress string
		for _, listener := range tunnelTCPListeners {
			tcpAddress = listener.Address()
		}
		for _, listener := range tunnelUDPListeners {
			udpAddress = listener.Address()
		}
		if tcpAddress == "" || udpAddress == "" {
			t.Fatal("tunnel endpoints did not start")
		}
		StopListener()
		tcp, err := net.Listen("tcp", tcpAddress)
		if err != nil {
			t.Errorf("stop left TCP tunnel bound at %s: %v", tcpAddress, err)
		} else {
			_ = tcp.Close()
		}
		udp, err := net.ListenPacket("udp", udpAddress)
		if err != nil {
			t.Errorf("stop left UDP tunnel bound at %s: %v", udpAddress, err)
		} else {
			_ = udp.Close()
		}
	}
}
