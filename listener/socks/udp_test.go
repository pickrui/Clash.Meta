package socks

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"
)

type udpTunnel struct {
	C.Tunnel
	packets chan *C.Metadata
}

func (t *udpTunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {
	packet.Drop()
	t.packets <- metadata
}

func TestUDPAppliesLANAddressPolicy(t *testing.T) {
	allowed, denied := inbound.AllowedIPs(), inbound.DisAllowedIPs()
	t.Cleanup(func() {
		inbound.SetAllowedIPs(allowed)
		inbound.SetDisAllowedIPs(denied)
	})
	inbound.SetAllowedIPs([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")})
	inbound.SetDisAllowedIPs([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})

	tunnel := &udpTunnel{packets: make(chan *C.Metadata, 1)}
	listener, err := NewUDP("127.0.0.1:0", tunnel)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("udp", listener.Address())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	packet, err := socks5.EncodeUDPPacket(socks5.ParseAddr("1.1.1.1:53"), []byte("query"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.Write(packet); err != nil {
		t.Fatal(err)
	}
	select {
	case <-tunnel.packets:
		t.Fatal("a datagram from a disallowed address reached the tunnel")
	case <-time.After(200 * time.Millisecond):
	}

	inbound.SetDisAllowedIPs(nil)
	if _, err := client.Write(packet); err != nil {
		t.Fatal(err)
	}
	select {
	case <-tunnel.packets:
	case <-time.After(2 * time.Second):
		t.Fatal("a datagram from an allowed address did not reach the tunnel")
	}
}
