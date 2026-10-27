package listener

import (
	"net"
	"path/filepath"
	"strconv"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	I "github.com/metacubex/mihomo/listener/inbound"
)

func TestInboundFailedStartReleasesEarlierPorts(t *testing.T) {
	factories := map[string]func(I.BaseOption) (C.InboundListener, error){
		"http":  func(o I.BaseOption) (C.InboundListener, error) { return I.NewHTTP(&I.HTTPOption{BaseOption: o}) },
		"socks": func(o I.BaseOption) (C.InboundListener, error) { return I.NewSocks(&I.SocksOption{BaseOption: o}) },
		"mixed": func(o I.BaseOption) (C.InboundListener, error) { return I.NewMixed(&I.MixedOption{BaseOption: o}) },
		"redir": func(o I.BaseOption) (C.InboundListener, error) { return I.NewRedir(&I.RedirOption{BaseOption: o}) },
		"sudoku": func(o I.BaseOption) (C.InboundListener, error) {
			return I.NewSudoku(&I.SudokuOption{BaseOption: o, Key: "failed-start-fixture"})
		},
		"tunnel": func(o I.BaseOption) (C.InboundListener, error) {
			return I.NewTunnel(&I.TunnelOption{BaseOption: o, Network: []string{"tcp"}, Target: "127.0.0.1:9"})
		},
	}
	for name, create := range factories {
		t.Run(name, func(t *testing.T) {
			first, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			second, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				first.Close()
				t.Fatal(err)
			}
			if first.Addr().(*net.TCPAddr).Port > second.Addr().(*net.TCPAddr).Port {
				first, second = second, first
			}
			defer second.Close()
			address := first.Addr().String()
			ports := strconv.Itoa(first.Addr().(*net.TCPAddr).Port) + "," + strconv.Itoa(second.Addr().(*net.TCPAddr).Port)
			first.Close()
			custom, err := create(I.BaseOption{NameStr: name, Listen: "127.0.0.1", Port: ports})
			if err != nil {
				t.Fatal(err)
			}
			defer custom.Close()
			if err := custom.Listen(nil); err == nil {
				t.Fatal("occupied later port did not fail")
			}
			probe, err := net.Listen("tcp", address)
			if err != nil {
				t.Fatalf("failed start retained its earlier TCP port: %v", err)
			}
			probe.Close()
			second.Close()
			if err := custom.Listen(nil); err != nil {
				t.Fatalf("retry after releasing occupied port: %v", err)
			}
		})
	}
}

func TestInboundUDPFailureReleasesTCP(t *testing.T) {
	for _, kind := range []string{"socks", "mixed", "tunnel"} {
		t.Run(kind, func(t *testing.T) {
			occupied, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer occupied.Close()
			options := I.BaseOption{NameStr: kind, Listen: "127.0.0.1", Port: strconv.Itoa(occupied.LocalAddr().(*net.UDPAddr).Port)}
			var custom C.InboundListener
			switch kind {
			case "socks":
				custom, err = I.NewSocks(&I.SocksOption{BaseOption: options, UDP: true})
			case "mixed":
				custom, err = I.NewMixed(&I.MixedOption{BaseOption: options, UDP: true})
			case "tunnel":
				custom, err = I.NewTunnel(&I.TunnelOption{BaseOption: options, Network: []string{"tcp", "udp"}, Target: "127.0.0.1:9"})
			}
			if err != nil {
				t.Fatal(err)
			}
			defer custom.Close()
			if err := custom.Listen(nil); err == nil {
				t.Fatal("occupied UDP port did not fail")
			}
			probe, err := net.Listen("tcp", occupied.LocalAddr().String())
			if err != nil {
				t.Fatalf("UDP failure retained already-started TCP listener: %v", err)
			}
			probe.Close()
			occupied.Close()
			if err := custom.Listen(nil); err != nil {
				t.Fatalf("retry after releasing occupied UDP port: %v", err)
			}
		})
	}
}

func TestFailedInboundReplacementRestoresWorkingListener(t *testing.T) {
	inboundMux.Lock()
	previous := inboundListeners
	inboundListeners = map[string]C.InboundListener{}
	inboundMux.Unlock()
	defer func() {
		PatchInboundListeners(nil, nil, true)
		inboundMux.Lock()
		inboundListeners = previous
		inboundMux.Unlock()
	}()
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(probe.Addr().(*net.TCPAddr).Port)
	address := probe.Addr().String()
	probe.Close()
	options := I.BaseOption{NameStr: "replacement-regression", Listen: "127.0.0.1", Port: port}
	old, err := I.NewHTTP(&I.HTTPOption{BaseOption: options})
	if err != nil {
		t.Fatal(err)
	}
	PatchInboundListeners(map[string]C.InboundListener{old.Name(): old}, nil, true)
	broken, err := I.NewHTTP(&I.HTTPOption{BaseOption: options, Certificate: filepath.Join(t.TempDir(), "invalid-certificate"), PrivateKey: filepath.Join(t.TempDir(), "invalid-key")})
	if err != nil {
		t.Fatal(err)
	}
	PatchInboundListeners(map[string]C.InboundListener{broken.Name(): broken}, nil, true)
	if p, err := net.Listen("tcp", address); err == nil {
		p.Close()
		t.Fatal("failed replacement stopped the previous working listener")
	}
	PatchInboundListeners(map[string]C.InboundListener{old.Name(): old}, nil, true)
	if p, err := net.Listen("tcp", address); err == nil {
		p.Close()
		t.Fatal("restoring the previous configuration skipped its closed listener")
	}
}
