package transport

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

type trackedPacketConn struct {
	net.PacketConn
	closed bool
}

func (c *trackedPacketConn) Close() error {
	c.closed = true
	return c.PacketConn.Close()
}

type trackingDialer struct {
	mu    sync.Mutex
	conns []*trackedPacketConn
}

func (d *trackingDialer) ListenPacket(net.Addr) (net.PacketConn, error) {
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	tracked := &trackedPacketConn{PacketConn: conn}
	d.mu.Lock()
	d.conns = append(d.conns, tracked)
	d.mu.Unlock()
	return tracked, nil
}

func (*trackingDialer) Context() context.Context { return context.Background() }

func (*trackingDialer) RemoteAddr(host string) (net.Addr, error) {
	return net.ResolveUDPAddr("udp", host)
}

func TestPortHoppingClosesEverySocket(t *testing.T) {
	dialer := &trackingDialer{}
	rAddr, _ := dialer.RemoteAddr("127.0.0.1:443")
	conn, err := (&ClientTransport{}).quicPacketConn("udp", rAddr, "1000-1001", nil, time.Minute, dialer)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	for index, socket := range dialer.conns {
		if !socket.closed {
			t.Errorf("socket %d of %d stayed open after the hopping connection closed", index+1, len(dialer.conns))
		}
	}
}
