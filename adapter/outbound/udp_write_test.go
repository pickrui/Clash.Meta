package outbound

import (
	"bytes"
	"errors"
	"net"
	"testing"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/transport/socks5"
)

type udpWriteRecorder struct {
	net.PacketConn
	packet  []byte
	addr    net.Addr
	failure error
}

func (r *udpWriteRecorder) WriteTo(p []byte, addr net.Addr) (int, error) {
	r.packet = bytes.Clone(p)
	r.addr = addr
	if r.failure != nil {
		return 0, r.failure
	}
	return len(p), nil
}

func TestUDPWriteReportsPayloadLength(t *testing.T) {
	relay := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1080}
	destination := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5353}
	for _, protocol := range []string{"socks5", "ssr"} {
		for _, payload := range [][]byte{nil, []byte("payload")} {
			t.Run(protocol+"/"+string(payload), func(t *testing.T) {
				recorder := &udpWriteRecorder{}
				var conn net.PacketConn = &socksPacketConn{PacketConn: recorder, rAddr: relay}
				if protocol == "ssr" {
					conn = &ssrPacketConn{EnhancePacketConn: N.NewEnhancePacketConn(recorder), rAddr: relay}
				}
				n, err := conn.WriteTo(payload, destination)
				if err != nil || n != len(payload) {
					t.Errorf("payload=%d returned=%d err=%v", len(payload), n, err)
				}
				wire, err := socks5.EncodeUDPPacket(socks5.ParseAddrToSocksAddr(destination), payload)
				if err != nil {
					t.Fatal(err)
				}
				if protocol == "ssr" {
					wire = wire[3:]
				}
				if !bytes.Equal(recorder.packet, wire) || recorder.addr != relay {
					t.Fatal("wire payload or relay destination changed")
				}
				failure := errors.New("write failed")
				recorder.failure = failure
				if n, err = conn.WriteTo(payload, destination); n != 0 || !errors.Is(err, failure) {
					t.Fatalf("failed write: %d, %v", n, err)
				}
			})
		}
	}
}
