package core

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/transport/hysteria/transport"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

type loopbackDialer struct{}

func (loopbackDialer) ListenPacket(net.Addr) (net.PacketConn, error) {
	return net.ListenUDP("udp", nil)
}

func (loopbackDialer) Context() context.Context { return context.Background() }

func (loopbackDialer) RemoteAddr(host string) (net.Addr, error) {
	return net.ResolveUDPAddr("udp", host)
}

// A v1 server that numbers UDP sessions per connection from 0, like the
// reference server, and echoes datagrams tagged with the connection number.
func startEchoServer(t *testing.T, maxStreams int64) (string, *atomic.Int32) {
	cert, key, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := quic.ListenAddr("127.0.0.1:0",
		&tls.Config{Certificates: []tls.Certificate{pair}, NextProtos: []string{"hysteria"}},
		&quic.Config{EnableDatagrams: true, MaxIncomingStreams: maxStreams})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	connections := &atomic.Int32{}
	go func() {
		for {
			conn, err := listener.Accept(context.Background())
			if err != nil {
				return
			}
			index := connections.Add(1)
			go serveEcho(conn, index)
		}
	}()
	return listener.Addr().String(), connections
}

func serveEcho(conn *quic.Conn, index int32) {
	control, err := conn.AcceptStream(context.Background())
	if err != nil {
		return
	}
	if _, err := ReadClientHello(control); err != nil {
		return
	}
	_ = WriteServerHello(control, ServerHello{OK: true, SendBPS: 1 << 20, RecvBPS: 1 << 20})
	go func() {
		for {
			raw, err := conn.ReceiveDatagram(context.Background())
			if err != nil {
				return
			}
			var message udpMessage
			if message.Unpack(raw) != nil {
				continue
			}
			message.Data = fmt.Appendf(nil, "conn%d:%s", index, message.Data)
			_ = conn.SendDatagram(message.Pack())
		}
	}()
	var nextSession uint32
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		request, err := ReadClientRequest(stream)
		if err != nil {
			continue
		}
		response := ServerResponse{OK: true}
		if request.UDP {
			response.UDPSessionID = nextSession
			nextSession++
		}
		_ = WriteServerResponse(stream, response)
	}
}

func TestStreamLimitKeepsTheSessionAndItsUDPFlows(t *testing.T) {
	// The control stream and two requests fill the server's stream limit.
	address, connections := startEchoServer(t, 3)
	client, err := NewClient(address, "", "udp", []byte("auth"),
		&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"hysteria"}, ServerName: "localhost", MinVersion: tls.VersionTLS13},
		&quic.Config{EnableDatagrams: true, KeepAlivePeriod: 10 * time.Second},
		&transport.ClientTransport{}, 1<<20, 1<<20, nil, nil, 10*time.Second, false)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	udp, err := client.DialUDP(loopbackDialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	tcp, err := client.DialTCP("example.com", 80, loopbackDialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()

	if extra, err := client.DialUDP(loopbackDialer{}); err == nil {
		extra.Close()
		t.Fatal("a dial beyond the stream limit succeeded")
	}
	if count := connections.Load(); count != 1 {
		t.Fatalf("the stream limit opened %d connections", count)
	}
	if err := udp.WriteTo([]byte("ping"), "192.0.2.1:53"); err != nil {
		t.Fatal(err)
	}
	reply := make(chan string, 1)
	go func() {
		data, _, err := udp.ReadFrom()
		if err == nil {
			reply <- string(data)
		}
	}()
	select {
	case got := <-reply:
		if got != "conn1:ping" {
			t.Fatalf("reply = %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the first UDP flow lost its replies")
	}
}
