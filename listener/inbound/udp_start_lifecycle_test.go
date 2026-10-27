package inbound_test

import (
	"context"
	"net"
	"reflect"
	"strconv"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/listener/sing_hysteria2"
)

type udpStartListenConfig struct {
	net.ListenConfig
	opened []net.PacketConn
}

func (l *udpStartListenConfig) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	conn, err := l.ListenConfig.ListenPacket(ctx, network, address)
	if err == nil {
		l.opened = append(l.opened, conn)
	}
	return conn, err
}

func TestUDPInboundFailedStartReleasesEarlierPorts(t *testing.T) {
	factories := map[string]func(inbound.BaseOption) (C.InboundListener, error){
		"tuic": func(o inbound.BaseOption) (C.InboundListener, error) {
			return inbound.NewTuic(&inbound.TuicOption{
				BaseOption: o, Certificate: tlsCertificate, PrivateKey: tlsPrivateKey,
				Users: map[string]string{userUUID: "password"},
			})
		},
		"hysteria2": func(o inbound.BaseOption) (C.InboundListener, error) {
			return inbound.NewHysteria2(&inbound.Hysteria2Option{
				BaseOption: o, Certificate: tlsCertificate, PrivateKey: tlsPrivateKey,
				Users: map[string]string{"user": "password"},
			})
		},
	}
	for name, create := range factories {
		t.Run(name, func(t *testing.T) {
			first, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer first.Close()
			second, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer second.Close()
			if first.LocalAddr().(*net.UDPAddr).Port > second.LocalAddr().(*net.UDPAddr).Port {
				first, second = second, first
			}
			address := first.LocalAddr().String()
			ports := strconv.Itoa(first.LocalAddr().(*net.UDPAddr).Port) + "," + strconv.Itoa(second.LocalAddr().(*net.UDPAddr).Port)
			if err := first.Close(); err != nil {
				t.Fatal(err)
			}
			listenConfig := &udpStartListenConfig{}
			t.Cleanup(func() {
				for _, conn := range listenConfig.opened {
					_ = conn.Close()
				}
			})
			custom, err := create(inbound.BaseOption{
				NameStr: name, Listen: "127.0.0.1", Port: ports, ListenConfigForAPI: listenConfig,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := custom.Listen(nil); err == nil {
				_ = custom.Close()
				t.Fatal("occupied later UDP port did not fail")
			}
			if len(listenConfig.opened) != 1 {
				t.Fatalf("allocated %d UDP sockets before the failed bind", len(listenConfig.opened))
			}
			probe, err := net.ListenPacket("udp", address)
			if err != nil {
				t.Fatalf("failed start retained its earlier UDP port: %v", err)
			}
			_ = probe.Close()
			_ = second.Close()
			if err := custom.Listen(nil); err != nil {
				t.Fatalf("retry after releasing occupied UDP port: %v", err)
			}
			if err := custom.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHysteria2MultiAddressOwnsIndependentRealmServices(t *testing.T) {
	stun, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer stun.Close()
	listener, err := sing_hysteria2.New(LC.Hysteria2Server{
		Listen: "127.0.0.1:0,127.0.0.1:0", Certificate: tlsCertificate, PrivateKey: tlsPrivateKey,
		Users: map[string]string{"user": "password"},
		RealmOpts: LC.Hysteria2RealmOption{
			Enable: true, ServerURL: "http://127.0.0.1:1", Token: "fixture", RealmID: "fixture",
			STUNServers: []string{stun.LocalAddr().String()},
		},
	}, &udpStartListenConfig{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	services := reflect.ValueOf(listener).Elem().FieldByName("services")
	if services.Len() != 2 {
		t.Fatalf("started %d services instead of two", services.Len())
	}
	first := services.Index(0).Elem().FieldByName("realmServer").Pointer()
	second := services.Index(1).Elem().FieldByName("realmServer").Pointer()
	if first == 0 || second == 0 || first == second {
		t.Fatal("listener addresses share the same Realm lifecycle owner")
	}
}
