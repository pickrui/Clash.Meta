package sing_shadowsocks_test

import (
	IN "github.com/metacubex/mihomo/listener/inbound"
	"net"
	"strconv"
	"sync"
	"testing"

	A "github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	SS "github.com/metacubex/mihomo/listener/sing_shadowsocks"
)

type idleTunnel struct{ C.Tunnel }

func reserveTCPAndUDP(t *testing.T) (net.Listener, net.PacketConn) {
	t.Helper()
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tcp.Close() })
	udp, err := net.ListenPacket("udp", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	return tcp, udp
}

func TestShadowSocksPartialBindRollback(t *testing.T) {
	for _, cipher := range []string{"chacha20-ietf-poly1305", "aes-128-cfb"} {
		t.Run(cipher, func(t *testing.T) {
			firstTCP, firstUDP := reserveTCPAndUDP(t)
			blockedTCP, secondUDP := reserveTCPAndUDP(t)
			first, second := firstTCP.Addr().String(), blockedTCP.Addr().String()
			firstTCP.Close()
			firstUDP.Close()
			secondUDP.Close()
			_, err := SS.New(LC.ShadowsocksServer{Listen: first + "," + second, Cipher: cipher, Password: "password", Udp: true}, &idleTunnel{}, A.WithInName("rollback-test"))
			if err == nil {
				t.Fatal("expected the second TCP bind to fail")
			}
			tcp, err := net.Listen("tcp", first)
			if err != nil {
				t.Fatalf("first TCP socket leaked after failure: %v", err)
			}
			tcp.Close()
			for _, addr := range []string{first, second} {
				udp, err := net.ListenPacket("udp", addr)
				if err != nil {
					t.Fatalf("UDP socket leaked after failure: %v", err)
				}
				udp.Close()
			}
		})
	}
}

func TestShadowSocksConcurrentClose(t *testing.T) {
	for _, cipher := range []string{"chacha20-ietf-poly1305", "aes-128-cfb"} {
		t.Run(cipher, func(t *testing.T) {
			tcp, udp := reserveTCPAndUDP(t)
			address := tcp.Addr().String()
			tcp.Close()
			udp.Close()
			listener, err := SS.New(LC.ShadowsocksServer{Listen: address, Cipher: cipher, Password: "password", Udp: true}, &idleTunnel{}, A.WithInName("close-test"))
			if err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			for range 16 {
				wg.Go(func() {
					if err := listener.Close(); err != nil {
						t.Error(err)
					}
				})
			}
			wg.Wait()
			rebound, err := net.Listen("tcp", address)
			if err != nil {
				t.Fatal(err)
			}
			rebound.Close()
			packet, err := net.ListenPacket("udp", address)
			if err != nil {
				t.Fatal(err)
			}
			packet.Close()
		})
	}
}

func TestShadowSocksCloseAfterFailedListen(t *testing.T) {
	for _, cipher := range []string{"chacha20-ietf-poly1305", "aes-128-cfb"} {
		t.Run(cipher, func(t *testing.T) {
			blocked, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer blocked.Close()
			port := blocked.Addr().(*net.TCPAddr).Port
			listener, err := IN.NewShadowSocks(&IN.ShadowSocksOption{
				BaseOption: IN.BaseOption{NameStr: "failed-listen", Listen: "127.0.0.1", Port: strconv.Itoa(port)},
				Cipher:     cipher, Password: "password",
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := listener.Listen(&idleTunnel{}); err == nil {
				t.Fatal("occupied port accepted")
			}
			if err := listener.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
