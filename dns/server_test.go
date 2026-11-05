package dns

import (
	"context"
	"net"
	"testing"
	"time"

	D "github.com/miekg/dns"
)

type largeReplyService struct{}

func (largeReplyService) ServeMsg(_ context.Context, query *D.Msg) (*D.Msg, error) {
	reply := new(D.Msg).SetReply(query)
	for i := 0; i < 150; i++ {
		reply.Answer = append(reply.Answer, &D.A{Hdr: D.RR_Header{Name: query.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, byte(i))})
	}
	return reply, nil
}

type dnsResponseRecorder struct {
	D.ResponseWriter
	remote net.Addr
	data   []byte
}

func (r *dnsResponseRecorder) RemoteAddr() net.Addr            { return r.remote }
func (r *dnsResponseRecorder) WriteMsg(msg *D.Msg) (err error) { r.data, err = msg.Pack(); return }

func TestServerTruncatesOnlyUDP(t *testing.T) {
	for _, tc := range []struct {
		name  string
		size  uint16
		tcp   bool
		limit int
	}{
		{"legacy", 0, false, 512}, {"small-edns", 100, false, 512},
		{"edns", 1232, false, 1232}, {"large-edns", 4096, false, 4096},
		{"tcp", 512, true, 65535},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query := new(D.Msg).SetQuestion("large-response.example.test.", D.TypeA)
			if tc.size > 0 {
				query.SetEdns0(tc.size, false)
			}
			writer := &dnsResponseRecorder{remote: &net.UDPAddr{}}
			if tc.tcp {
				writer.remote = &net.TCPAddr{}
			}
			replying := &Server{}
			replying.SetService(largeReplyService{})
			(serverHandler{Server: replying, isUDP: !tc.tcp}).ServeDNS(writer, query)
			if len(writer.data) > tc.limit {
				t.Fatalf("response size %d exceeds %d", len(writer.data), tc.limit)
			}
			reply := new(D.Msg)
			if err := reply.Unpack(writer.data); err != nil {
				t.Fatal(err)
			}
			wantTruncated := tc.limit < 2400
			if reply.Truncated != wantTruncated {
				t.Fatalf("TC=%t, want %t", reply.Truncated, wantTruncated)
			}
			if !wantTruncated && len(reply.Answer) != 150 {
				t.Fatalf("lost answers: %d", len(reply.Answer))
			}
		})
	}
}

type plainListenConfig struct{ net.ListenConfig }

func (c plainListenConfig) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	return c.ListenConfig.Listen(ctx, network, address)
}

func (c plainListenConfig) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	return c.ListenConfig.ListenPacket(ctx, network, address)
}

func TestReCreateServerClosesAServerItJustOpened(t *testing.T) {
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.LocalAddr().String()
	probe.Close()
	t.Cleanup(func() { ReCreateServer("", nil, nil) })

	for range 20 {
		ReCreateServer(addr, plainListenConfig{}, largeReplyService{})
		ReCreateServer("", nil, nil)
		udp, err := net.ListenPacket("udp", addr)
		if err != nil {
			t.Fatalf("the UDP listener outlived its close: %v", err)
		}
		udp.Close()
		tcp, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatalf("the TCP listener outlived its close: %v", err)
		}
		tcp.Close()
	}
}

type heldService struct {
	entered chan struct{}
	release chan struct{}
}

func (s heldService) ServeMsg(_ context.Context, query *D.Msg) (*D.Msg, error) {
	s.entered <- struct{}{}
	<-s.release
	return new(D.Msg).SetReply(query), nil
}

func freeDNSAddress(t *testing.T) string {
	t.Helper()
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	return probe.LocalAddr().String()
}

func TestReCreateServerFreesThePortWhileAQueryIsInFlight(t *testing.T) {
	addr := freeDNSAddress(t)
	t.Cleanup(func() { ReCreateServer("", nil, nil) })
	service := heldService{entered: make(chan struct{}), release: make(chan struct{})}
	defer close(service.release)
	ReCreateServer(addr, plainListenConfig{}, service)
	go func() {
		query := new(D.Msg)
		query.SetQuestion("held.test.", D.TypeA)
		_, _, _ = (&D.Client{Net: "udp", Timeout: 5 * time.Second}).Exchange(query, addr)
	}()
	<-service.entered

	started := time.Now()
	ReCreateServer("", nil, nil)
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("closing waited %s for the query in flight", elapsed)
	}
	udp, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("the port stayed bound while the query ran: %v", err)
	}
	udp.Close()
}

func TestReCreateServerRetriesAnAddressItCouldNotBind(t *testing.T) {
	addr := freeDNSAddress(t)
	t.Cleanup(func() { ReCreateServer("", nil, nil) })
	udp, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	ReCreateServer(addr, plainListenConfig{}, largeReplyService{})
	udp.Close()
	tcp.Close()

	ReCreateServer(addr, plainListenConfig{}, largeReplyService{})
	if probe, err := net.ListenPacket("udp", addr); err == nil {
		probe.Close()
		t.Fatal("the listener was not opened once the port was free")
	}
}
