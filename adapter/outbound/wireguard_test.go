package outbound

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"sync"
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

func initTestWireGuard(t *testing.T, w *WireGuard) {
	t.Helper()
	w.bind = wireguard.NewClientBind(w.runCtx, wgSingErrorHandler{w.Name()}, wireguardTestDialer{}, true, netip.MustParseAddrPort("127.0.0.1:51820"), [3]byte{})
	if err := w.init0(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func newLazyWireGuard(t *testing.T) *WireGuard {
	t.Helper()
	w, err := NewWireGuard(WireGuardOption{
		Name: "lazy-test", Ip: "10.0.0.1", Workers: 1, IPStack: IPStackOption{Mode: ipStackMips},
		PrivateKey:          base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
		WireGuardPeerOption: WireGuardPeerOption{Server: "127.0.0.1", Port: 51820, PublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	if w.device != nil || w.tunDevice != nil {
		t.Fatal("constructor allocated a device")
	}
	return w
}

func TestWireGuardLazyLifetime(t *testing.T) {
	w := newLazyWireGuard(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := w.init0(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled init: %v", err)
	}
	if w.device != nil || w.tunDevice != nil {
		t.Fatal("canceled init allocated a device")
	}
	initTestWireGuard(t, w)
	first := w.device
	if err := w.init0(context.Background()); err != nil || w.device != first {
		t.Fatalf("repeated init replaced device: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.init0(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("init after close: %v", err)
	}
}

func TestWireGuardCloseBeforeAndDuringInitialization(t *testing.T) {
	w := newLazyWireGuard(t)
	_ = w.Close()
	if err := w.init0(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("closed init: %v", err)
	}
	if w.device != nil {
		t.Fatal("closed adapter allocated device")
	}
	w = newLazyWireGuard(t)
	w.bind = wireguard.NewClientBind(w.runCtx, wgSingErrorHandler{w.Name()}, wireguardTestDialer{}, true, netip.MustParseAddrPort("127.0.0.1:51820"), [3]byte{})
	var group sync.WaitGroup
	group.Add(2)
	go func() { defer group.Done(); _ = w.init0(context.Background()) }()
	go func() { defer group.Done(); _ = w.Close() }()
	group.Wait()
	if w.runCtx.Err() == nil {
		t.Fatal("lifetime remained active")
	}
}
