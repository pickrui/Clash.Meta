package inbound_test

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"

	"github.com/stretchr/testify/assert"
)

func TestInboundHysteria2LazyUDPAndTCP(t *testing.T) {
	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()
	tunnel.HandleUDPPacketFn = func(packet C.UDPPacket, metadata *C.Metadata) {
		defer packet.Drop()
		_, _ = packet.WriteBack(packet.Data(), net.UDPAddrFromAddrPort(netip.AddrPortFrom(metadata.DstIP, metadata.DstPort)))
	}
	in, err := inbound.NewHysteria2(&inbound.Hysteria2Option{
		BaseOption: inbound.BaseOption{NameStr: "lazy-hysteria2", Listen: "127.0.0.1", Port: "0"},
		Users:      map[string]string{"test": userUUID}, Certificate: tlsCertificate, PrivateKey: tlsPrivateKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := in.Listen(tunnel); err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	addr, err := netip.ParseAddrPort(in.Address())
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(int(addr.Port()))
	alpn := []string{"h3"}
	out, err := outbound.NewHysteria2(outbound.Hysteria2Option{
		BasicOption: outbound.BasicOption{DialerForAPI: tunnel.NewDialer(), TunnelForAPI: tunnel},
		Name:        "lazy-hysteria2", Server: addr.Addr().String(), Ports: port + "-" + port,
		Password: userUUID, Fingerprint: tlsFingerprint, ALPN: alpn,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	alpn[0] = "changed-after-construction"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	destination := netip.MustParseAddrPort("192.0.2.10:5353")
	packet, err := out.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, DstIP: destination.Addr(), DstPort: destination.Port()})
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	stop := context.AfterFunc(ctx, func() { _ = packet.Close() })
	defer stop()
	payload := bytes.Repeat([]byte{0, 0xff, 0x55, 0xaa}, 513)
	if n, err := packet.WriteTo(payload, net.UDPAddrFromAddrPort(destination)); err != nil || n != len(payload) {
		t.Fatalf("UDP write = %d: %v", n, err)
	}
	data := make([]byte, len(payload)+1)
	n, source, err := packet.ReadFrom(data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data[:n], payload) || source.String() != destination.String() {
		t.Fatalf("UDP response changed: length=%d source=%v", n, source)
	}
	tunnel.DoSequentialTest(t, out)
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, _, err := packet.ReadFrom(data); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("UDP read succeeded after closing the outbound")
		}
	case <-time.After(time.Second):
		t.Fatal("closing the outbound did not release its UDP reader")
	}
}

func testInboundHysteria2(t *testing.T, inboundOptions inbound.Hysteria2Option, outboundOptions outbound.Hysteria2Option) {
	t.Parallel()
	inboundOptions.BaseOption = inbound.BaseOption{
		NameStr: "hysteria2_inbound",
		Listen:  "127.0.0.1",
		Port:    "0",
	}
	inboundOptions.Users = map[string]string{"test": userUUID}
	in, err := inbound.NewHysteria2(&inboundOptions)
	if !assert.NoError(t, err) {
		return
	}

	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()

	err = in.Listen(tunnel)
	if !assert.NoError(t, err) {
		return
	}
	defer in.Close()

	addrPort, err := netip.ParseAddrPort(in.Address())
	if !assert.NoError(t, err) {
		return
	}

	outboundOptions.Name = "hysteria2_outbound"
	outboundOptions.Server = addrPort.Addr().String()
	outboundOptions.Port = int(addrPort.Port())
	outboundOptions.Password = userUUID
	outboundOptions.DialerForAPI = tunnel.NewDialer()
	outboundOptions.TunnelForAPI = tunnel

	out, err := outbound.NewHysteria2(outboundOptions)
	if !assert.NoError(t, err) {
		return
	}
	defer out.Close()

	tunnel.DoTest(t, out)
}

func testInboundHysteria2TLS(t *testing.T, inboundOptions inbound.Hysteria2Option, outboundOptions outbound.Hysteria2Option) {
	testInboundHysteria2(t, inboundOptions, outboundOptions)
	if winGo120 {
		return // subsequent tests frequently fail; skipping them for now.
	}
	t.Run("ECH", func(t *testing.T) {
		inboundOptions := inboundOptions
		outboundOptions := outboundOptions
		inboundOptions.EchKey = echKeyPem
		outboundOptions.ECHOpts = outbound.ECHOptions{
			Enable: true,
			Config: echConfigBase64,
		}
		testInboundHysteria2(t, inboundOptions, outboundOptions)
	})
	t.Run("mTLS", func(t *testing.T) {
		inboundOptions := inboundOptions
		outboundOptions := outboundOptions
		inboundOptions.ClientAuthCert = tlsAuthCertificate
		outboundOptions.Certificate = tlsAuthCertificate
		outboundOptions.PrivateKey = tlsAuthPrivateKey
		testInboundHysteria2(t, inboundOptions, outboundOptions)
	})
	t.Run("mTLS+ECH", func(t *testing.T) {
		inboundOptions := inboundOptions
		outboundOptions := outboundOptions
		inboundOptions.ClientAuthCert = tlsAuthCertificate
		outboundOptions.Certificate = tlsAuthCertificate
		outboundOptions.PrivateKey = tlsAuthPrivateKey
		inboundOptions.EchKey = echKeyPem
		outboundOptions.ECHOpts = outbound.ECHOptions{
			Enable: true,
			Config: echConfigBase64,
		}
		testInboundHysteria2(t, inboundOptions, outboundOptions)
	})
}

func TestInboundHysteria2_TLS(t *testing.T) {
	inboundOptions := inbound.Hysteria2Option{
		Certificate: tlsCertificate,
		PrivateKey:  tlsPrivateKey,
	}
	outboundOptions := outbound.Hysteria2Option{
		Fingerprint: tlsFingerprint,
	}
	testInboundHysteria2TLS(t, inboundOptions, outboundOptions)
}

func TestInboundHysteria2_Salamander(t *testing.T) {
	inboundOptions := inbound.Hysteria2Option{
		Certificate:  tlsCertificate,
		PrivateKey:   tlsPrivateKey,
		Obfs:         "salamander",
		ObfsPassword: userUUID,
	}
	outboundOptions := outbound.Hysteria2Option{
		Fingerprint:  tlsFingerprint,
		Obfs:         "salamander",
		ObfsPassword: userUUID,
	}
	testInboundHysteria2TLS(t, inboundOptions, outboundOptions)
}

func TestInboundHysteria2_Gecko(t *testing.T) {
	inboundOptions := inbound.Hysteria2Option{
		Certificate:  tlsCertificate,
		PrivateKey:   tlsPrivateKey,
		Obfs:         "gecko",
		ObfsPassword: userUUID,
	}
	outboundOptions := outbound.Hysteria2Option{
		Fingerprint:  tlsFingerprint,
		Obfs:         "gecko",
		ObfsPassword: userUUID,
	}
	testInboundHysteria2TLS(t, inboundOptions, outboundOptions)
}

func TestInboundHysteria2_Brutal(t *testing.T) {
	inboundOptions := inbound.Hysteria2Option{
		Certificate: tlsCertificate,
		PrivateKey:  tlsPrivateKey,
		Up:          "30 Mbps",
		Down:        "200 Mbps",
	}
	outboundOptions := outbound.Hysteria2Option{
		Fingerprint: tlsFingerprint,
		Up:          "30 Mbps",
		Down:        "200 Mbps",
	}
	testInboundHysteria2TLS(t, inboundOptions, outboundOptions)
}
