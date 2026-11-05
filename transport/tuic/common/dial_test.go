package common

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/tuic/internal/testutil"
	"github.com/metacubex/quic-go"
)

type capturePacketConn struct {
	net.PacketConn
	first                chan []byte
	closed               chan struct{}
	writeOnce, closeOnce sync.Once
}

func (c *capturePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.writeOnce.Do(func() { c.first <- append([]byte(nil), p...) })
	return c.PacketConn.WriteTo(p, addr)
}
func (c *capturePacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.PacketConn.Close()
}

type loopbackPacketDialer struct{ conn *capturePacketConn }

func (d *loopbackPacketDialer) ListenPacket(ctx context.Context, network, address string, remote netip.AddrPort) (net.PacketConn, error) {
	var lc net.ListenConfig
	c, err := lc.ListenPacket(ctx, "udp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	d.conn = &capturePacketConn{PacketConn: c, first: make(chan []byte, 1), closed: make(chan struct{})}
	return d.conn, nil
}

func TestDialQuicConnectionIDAndEarlyHandshake(t *testing.T) {
	for _, tc := range []struct {
		name         string
		option       DialQuicOption
		sourceLength int
	}{
		{"default", DialQuicOption{}, 0},
		{"early", DialQuicOption{Early: true}, 0},
		{"masque", DialQuicOption{ConnectionIDLength: 20}, 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serverTLS, clientTLS := testutil.TLSConfigs(t)
			server, err := quic.ListenAddr("127.0.0.1:0", serverTLS, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			d := &loopbackPacketDialer{}
			pc, conn, err := DialQuic(ctx, server.Addr().String(), nil, d, clientTLS, nil, tc.option)
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			defer conn.CloseWithError(0, "test complete")
			accepted, err := server.Accept(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer accepted.CloseWithError(0, "test complete")
			select {
			case <-conn.HandshakeComplete():
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			initial := <-d.conn.first
			if len(initial) < 7 || initial[0]&0x80 == 0 {
				t.Fatalf("invalid initial packet: %x", initial)
			}
			sourceOffset := 6 + int(initial[5])
			if sourceOffset >= len(initial) {
				t.Fatal("truncated destination ID")
			}
			if got := int(initial[sourceOffset]); got != tc.sourceLength {
				t.Fatalf("source connection ID length = %d, want %d", got, tc.sourceLength)
			}
		})
	}
}

func TestDialQuicHandshakeFailureClosesPacketConn(t *testing.T) {
	serverTLS, clientTLS := testutil.TLSConfigs(t)
	server, err := quic.ListenAddr("127.0.0.1:0", serverTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	clientTLS.ServerName = "untrusted.test"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	d := &loopbackPacketDialer{}
	pc, conn, err := DialQuic(ctx, server.Addr().String(), nil, d, clientTLS, nil, DialQuicOption{ConnectionIDLength: 20})
	if err == nil || pc != nil || conn != nil {
		t.Fatalf("untrusted peer result: pc=%v conn=%v err=%v", pc, conn, err)
	}
	if d.conn == nil {
		t.Fatal("test did not attempt handshake")
	}
	select {
	case <-d.conn.closed:
	case <-ctx.Done():
		t.Fatal("failed handshake leaked packet connection")
	}
}
