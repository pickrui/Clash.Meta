package tunnel

import (
	"context"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

type tcpOnlyDNSProxy struct{ C.ProxyAdapter }

func (*tcpOnlyDNSProxy) Name() string     { return "tcp-only" }
func (*tcpOnlyDNSProxy) SupportUDP() bool { return false }
func (*tcpOnlyDNSProxy) String() string   { panic("proxy must not be formatted") }

func TestDNSDialerReportsUnsupportedUDPByName(t *testing.T) {
	dialer := NewDNSDialer(nil, &tcpOnlyDNSProxy{}, "")
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
