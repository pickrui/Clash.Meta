package listener_test

import (
	"net"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/anytls"
	LC "github.com/metacubex/mihomo/listener/config"
	httpListener "github.com/metacubex/mihomo/listener/http"
	"github.com/metacubex/mihomo/listener/mixed"
	"github.com/metacubex/mihomo/listener/socks"
)

func TestAuthListenerClosesSocketWhenTLSSetupFails(t *testing.T) {
	constructors := map[string]func(LC.AuthServer, C.Tunnel) error{
		"http": func(config LC.AuthServer, tunnel C.Tunnel) error {
			_, err := httpListener.NewWithConfig(config, tunnel)
			return err
		},
		"socks": func(config LC.AuthServer, tunnel C.Tunnel) error {
			_, err := socks.NewWithConfig(config, tunnel)
			return err
		},
		"mixed": func(config LC.AuthServer, tunnel C.Tunnel) error {
			_, err := mixed.NewWithConfig(config, tunnel)
			return err
		},
	}

	for name, construct := range constructors {
		t.Run(name, func(t *testing.T) {
			probe, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address := probe.Addr().String()
			if err := probe.Close(); err != nil {
				t.Fatal(err)
			}

			err = construct(LC.AuthServer{
				Listen:      address,
				Certificate: "invalid",
				PrivateKey:  "invalid",
			}, nil)
			if err == nil {
				t.Fatal("expected invalid TLS configuration to fail")
			}

			rebound, err := net.Listen("tcp", address)
			if err != nil {
				t.Fatalf("listener retained %s after setup failure: %v", address, err)
			}
			_ = rebound.Close()
		})
	}
}

func TestAnyTLSClosesSocketsWhenSetupFails(t *testing.T) {
	firstProbe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	firstAddress := firstProbe.Addr().String()
	if err := firstProbe.Close(); err != nil {
		t.Fatal(err)
	}

	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()

	_, err = anytls.New(LC.AnyTLSServer{
		Listen:        firstAddress + "," + occupied.Addr().String(),
		AllowInsecure: true,
	}, nil)
	if err == nil {
		t.Fatal("expected second address binding to fail")
	}

	rebound, err := net.Listen("tcp", firstAddress)
	if err != nil {
		t.Fatalf("AnyTLS retained first listener after setup failure: %v", err)
	}
	_ = rebound.Close()
}

func TestAnyTLSClosesSocketWhenCertificateIsRequired(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.Addr().String()
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = anytls.New(LC.AnyTLSServer{Listen: address}, nil)
	if err == nil {
		t.Fatal("expected certificate policy to reject the listener")
	}

	rebound, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("AnyTLS retained listener after certificate rejection: %v", err)
	}
	_ = rebound.Close()
}
