package outbound

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	wireguard "github.com/metacubex/sing-wireguard"
	M "github.com/metacubex/sing/common/metadata"
)

type wireguardTestDialer struct{ packet *wireguardTestPacketConn }

func (d wireguardTestDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("unexpected connected dial")
}
func (d wireguardTestDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return d.packet, nil
}

type wireguardTestPacketConn struct {
	net.PacketConn
	payload     []byte
	destination net.Addr
}

func (c *wireguardTestPacketConn) WriteTo(p []byte, d net.Addr) (int, error) {
	c.payload = bytes.Clone(p)
	c.destination = d
	return len(p), nil
}
func (c *wireguardTestPacketConn) Close() error { return nil }

func TestWireGuardUsesPerPeerReservedBytes(t *testing.T) {
	packet := &wireguardTestPacketConn{}
	defaults := [3]byte{9, 8, 7}
	bind := wireguard.NewClientBind(context.Background(), nil, wireguardTestDialer{packet}, false, netip.AddrPort{}, defaults)
	if _, _, err := bind.Open(0); err != nil {
		t.Fatal(err)
	}
	defer bind.Close()
	w := &WireGuard{bind: bind, serverAddrMap: make(map[M.Socksaddr]netip.AddrPort), option: WireGuardOption{
		WireGuardPeerOption: WireGuardPeerOption{Reserved: defaults[:]},
		Peers: []WireGuardPeerOption{
			{Server: "192.0.2.1", Port: 51820, Reserved: []byte{1, 2, 3}},
			{Server: "192.0.2.2", Port: 51820, Reserved: []byte{4, 5, 6}},
			{Server: "192.0.2.3", Port: 51820},
		},
	}}
	if _, err := w.genIpcConf(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	for _, peer := range w.option.Peers {
		addr := peer.Addr().AddrPort()
		data := []byte{1, 0, 0, 0, 42}
		if err := bind.Send([][]byte{data}, wireguard.Endpoint(addr)); err != nil {
			t.Fatal(err)
		}
		want := peer.Reserved
		if len(want) == 0 {
			want = defaults[:]
		}
		if !bytes.Equal(packet.payload[1:4], want) || packet.destination.String() != addr.String() {
			t.Errorf("peer=%s got=%v, want=%v", addr, packet.payload[1:4], want)
		}
	}
}
