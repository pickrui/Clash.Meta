package tunnel_test

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
)

type tcpOnlyDNSProxy struct{ C.ProxyAdapter }

func (*tcpOnlyDNSProxy) Name() string     { return "tcp-only" }
func (*tcpOnlyDNSProxy) SupportUDP() bool { return false }
func (*tcpOnlyDNSProxy) String() string   { panic("proxy must not be formatted") }

func TestDNSDialerReportsUnsupportedUDPByName(t *testing.T) {
	dialer := tunnel.NewDNSDialer(nil, &tcpOnlyDNSProxy{}, "")
	want := "proxy adapter [tcp-only] UDP is not supported"
	t.Run("DialContext", func(t *testing.T) {
		conn, err := dialer.DialContext(context.Background(), "udp", "192.0.2.1:53")
		if conn != nil || err == nil || err.Error() != want {
			t.Fatalf("got %v, %v", conn, err)
		}
	})
	t.Run("ListenPacket", func(t *testing.T) {
		conn, err := dialer.ListenPacket(context.Background(), "udp", "192.0.2.1:53")
		if conn != nil || err == nil || err.Error() != want {
			t.Fatalf("got %v, %v", conn, err)
		}
	})
}

func TestDNSPacketConnAddressFamilies(t *testing.T) {
	previousIPv6 := resolver.DisableIPv6.Swap(false)
	t.Cleanup(func() { resolver.DisableIPv6.Store(previousIPv6) })
	for _, host := range []string{"127.0.0.1", "::ffff:127.0.0.1", "::1"} {
		for _, transport := range []string{"direct", "shadowsocks"} {
			t.Run(host+"/"+transport, func(t *testing.T) {
				t.Parallel()
				ipv4 := net.ParseIP(host).To4() != nil
				network := "udp6"
				if ipv4 {
					network = "udp4"
				}
				server, err := net.ListenPacket(network, net.JoinHostPort(host, "0"))
				if err != nil {
					t.Fatal(err)
				}
				defer server.Close()
				port := server.LocalAddr().(*net.UDPAddr).Port
				var proxy C.ProxyAdapter
				if transport == "shadowsocks" {
					ss, err := outbound.NewShadowSocks(outbound.ShadowSocksOption{
						Name: "udp-family-test", Server: host, Port: port, Cipher: "none", UDP: true,
					})
					if err != nil {
						t.Fatal(err)
					}
					defer ss.Close()
					proxy = ss
				}
				pc, err := tunnel.NewDNSDialer(nil, proxy, "").ListenPacket(t.Context(), "udp", net.JoinHostPort(host, strconv.Itoa(port)))
				if err != nil {
					t.Fatal(err)
				}
				defer pc.Close()
				localAddr := pc.LocalAddr()
				if custom, ok := localAddr.(N.CustomAddr); ok {
					localAddr = custom.RawAddr()
				}
				if local := localAddr.(*net.UDPAddr); (local.IP.To4() != nil) != ipv4 {
					t.Fatalf("single-peer socket %s does not match server %s", local, host)
				}
				deadline := time.Now().Add(3 * time.Second)
				if err := pc.SetDeadline(deadline); err != nil {
					t.Fatal(err)
				}
				if err := server.SetDeadline(deadline); err != nil {
					t.Fatal(err)
				}
				if _, err := pc.WriteTo([]byte("probe"), server.LocalAddr()); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 1024)
				n, from, err := server.ReadFrom(buf)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := server.WriteTo(buf[:n], from); err != nil {
					t.Fatal(err)
				}
				n, _, err = pc.ReadFrom(buf)
				if err != nil {
					t.Fatal(err)
				}
				if string(buf[:n]) != "probe" {
					t.Fatalf("invalid UDP reply: %q", buf[:n])
				}
			})
		}
	}
}
