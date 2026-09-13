package tuic

import (
	"net"
	"testing"

	"github.com/metacubex/mihomo/transport/tuic/internal/testutil"
)

func TestServerClampsV5UDPRelaySize(t *testing.T) {
	for _, size := range []int{64, MaxFragSizeV5, MaxFragSizeV5 + 1, 65535} {
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		tlsConfig, _ := testutil.TLSConfigs(t)
		option := &ServerOption{TlsConfig: tlsConfig, Tokens: [][32]byte{{1}}, Users: map[[16]byte]string{{1}: "test"}, MaxUdpRelayPacketSize: size}
		server, err := NewServer(option, pc)
		if err != nil {
			_ = pc.Close()
			t.Fatal(err)
		}
		got := server.optionV5.MaxUdpRelayPacketSize
		v4Size := server.optionV4.MaxUdpRelayPacketSize
		_ = server.Close()
		_ = pc.Close()
		if got != min(size, MaxFragSizeV5) {
			t.Errorf("configured=%d got=%d, want=%d", size, got, min(size, MaxFragSizeV5))
		}
		if v4Size != size || option.MaxUdpRelayPacketSize != size {
			t.Fatal("V5 clamp modified shared or V4 options")
		}
	}
}
