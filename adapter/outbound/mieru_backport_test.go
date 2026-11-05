package outbound

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mieruconstant "github.com/enfein/mieru/v3/apis/constant"
	mierumodel "github.com/enfein/mieru/v3/apis/model"
	mieruserver "github.com/enfein/mieru/v3/apis/server"
	mierutp "github.com/enfein/mieru/v3/apis/trafficpattern"
	pb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/protocol"
	C "github.com/metacubex/mihomo/constant"
	"google.golang.org/protobuf/proto"
)

func TestMieruSessionZeroLengthRead(t *testing.T) {
	session := protocol.NewSession(1, true, 1400, nil, nil)
	defer session.Close()
	result := make(chan error, 1)
	go func() { _, err := session.Read(nil); result <- err }()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("empty read: %v", err)
		}
	case <-time.After(time.Second):
		_ = session.Close()
		<-result
		t.Fatal("zero-length read blocked waiting for a network segment")
	}
}

// Factories hand the server already-bound loopback sockets. This avoids the
// close-and-rebind race and prevents the library from listening on all interfaces.
type mieruLoopbackSockets struct {
	stream net.Listener
	packet net.PacketConn
	used   atomic.Bool
}

func (s *mieruLoopbackSockets) Listen(context.Context, string, string) (net.Listener, error) {
	if s.stream == nil || s.used.Swap(true) {
		return nil, fmt.Errorf("unexpected Mieru stream listener")
	}
	return s.stream, nil
}
func (s *mieruLoopbackSockets) ListenPacket(context.Context, string, string) (net.PacketConn, error) {
	if s.packet == nil || s.used.Swap(true) {
		return nil, fmt.Errorf("unexpected Mieru packet listener")
	}
	return s.packet, nil
}

func mieruTestPattern(mode pb.LowEntropyMode) *pb.TrafficPattern {
	if mode == pb.LowEntropyMode_LOW_ENTROPY_MODE_OFF {
		return nil
	}
	return &pb.TrafficPattern{LowEntropy: &pb.LowEntropyPattern{Mode: mode.Enum(), MaskRotation: pb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_ROTATE_RIGHT_3.Enum()}}
}

func newMieruLoopbackPeer(t *testing.T, transport string, pattern *pb.TrafficPattern) (int, <-chan *mierumodel.Request) {
	t.Helper()
	sockets := &mieruLoopbackSockets{}
	var port int
	var err error
	var kind pb.TransportProtocol
	if transport == "TCP" {
		sockets.stream, err = net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = sockets.stream.Close() })
		port = sockets.stream.Addr().(*net.TCPAddr).Port
		kind = pb.TransportProtocol_TCP
	} else {
		sockets.packet, err = net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = sockets.packet.Close() })
		port = sockets.packet.LocalAddr().(*net.UDPAddr).Port
		kind = pb.TransportProtocol_UDP
	}
	server := mieruserver.NewServer()
	if err := server.Store(&mieruserver.ServerConfig{
		Config: &pb.ServerConfig{
			PortBindings:   []*pb.PortBinding{{Port: proto.Int32(int32(port)), Protocol: kind.Enum()}},
			Users:          []*pb.User{{Name: proto.String("loopback-user"), Password: proto.String("loopback-password")}},
			TrafficPattern: pattern,
		},
		StreamListenerFactory: sockets, PacketListenerFactory: sockets,
	}); err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	requests := make(chan *mierumodel.Request, 8)
	done := make(chan struct{})
	var stopping atomic.Bool
	var lock sync.Mutex
	var connections []net.Conn
	var echoes sync.WaitGroup
	go func() {
		defer close(done)
		defer echoes.Wait()
		for {
			conn, req, err := server.Accept()
			if err != nil {
				if !stopping.Load() {
					t.Errorf("Mieru accept: %v", err)
				}
				return
			}
			lock.Lock()
			connections = append(connections, conn)
			lock.Unlock()
			requests <- req
			echoes.Add(1)
			go func() {
				defer echoes.Done()
				defer conn.Close()
				response := mierumodel.Response{Reply: mieruconstant.Socks5ReplySuccess, BindAddr: mierumodel.AddrSpec{IP: net.IPv4(127, 0, 0, 1), Port: 1}}
				if err := response.WriteToSocks5(conn); err != nil {
					if !stopping.Load() {
						t.Errorf("Mieru response: %v", err)
					}
					return
				}
				// Echo the stream, including framed SOCKS UDP packets, without forwarding.
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	t.Cleanup(func() {
		stopping.Store(true)
		_ = server.Stop()
		lock.Lock()
		for _, conn := range connections {
			_ = conn.Close()
		}
		lock.Unlock()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("Mieru peer did not stop")
		}
	})
	return port, requests
}

func TestMieruLoopbackTransports(t *testing.T) {
	for _, transport := range []string{"TCP", "UDP"} {
		for _, mode := range []pb.LowEntropyMode{pb.LowEntropyMode_LOW_ENTROPY_MODE_OFF, pb.LowEntropyMode_LOW_ENTROPY_MODE_32, pb.LowEntropyMode_LOW_ENTROPY_MODE_40, pb.LowEntropyMode_LOW_ENTROPY_MODE_48, pb.LowEntropyMode_LOW_ENTROPY_MODE_56} {
			t.Run(transport+"/"+mode.String(), func(t *testing.T) {
				pattern := mieruTestPattern(mode)
				port, requests := newMieruLoopbackPeer(t, transport, pattern)
				client, err := NewMieru(MieruOption{Name: "loopback", Server: "127.0.0.1", Port: port, Transport: transport, UserName: "loopback-user", Password: "loopback-password", UDP: true, TrafficPattern: mierutp.Encode(pattern)})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = client.Close() })
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				stream, err := client.DialContext(ctx, &C.Metadata{Host: "echo.test", DstPort: 443, NetWork: C.TCP})
				if err != nil {
					t.Fatal(err)
				}
				defer stream.Close()
				stopStream := context.AfterFunc(ctx, func() { _ = stream.Close() })
				defer stopStream()
				req := <-requests
				if req.Command != mieruconstant.Socks5ConnectCmd || req.DstAddr.FQDN != "echo.test" || req.DstAddr.Port != 443 {
					t.Fatalf("TCP request changed: %v", req)
				}
				payload := bytes.Repeat([]byte{0, 0xff, 0x55, 0xaa, 0x42}, 4097)
				if n, err := stream.Write(payload); err != nil || n != len(payload) {
					t.Fatalf("TCP write=%d: %v", n, err)
				}
				echoed := make([]byte, len(payload))
				if _, err := io.ReadFull(stream, echoed); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(echoed, payload) {
					t.Fatal("TCP payload changed")
				}
				_ = stream.Close()

				destination := netip.MustParseAddrPort("192.0.2.10:5353")
				packet, err := client.ListenPacketContext(ctx, &C.Metadata{DstIP: destination.Addr(), DstPort: destination.Port(), NetWork: C.UDP})
				if err != nil {
					t.Fatal(err)
				}
				defer packet.Close()
				stopPacket := context.AfterFunc(ctx, func() { _ = packet.Close() })
				defer stopPacket()
				req = <-requests
				if req.Command != mieruconstant.Socks5UDPAssociateCmd {
					t.Fatalf("UDP request changed: %v", req)
				}
				payload = payload[:4097]
				if n, err := packet.WriteTo(payload, net.UDPAddrFromAddrPort(destination)); err != nil || n != len(payload) {
					t.Fatalf("UDP write=%d: %v", n, err)
				}
				echoed = make([]byte, len(payload)+1)
				n, addr, err := packet.ReadFrom(echoed)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(echoed[:n], payload) || addr.String() != destination.String() {
					t.Fatalf("UDP packet changed: len=%d addr=%v", n, addr)
				}
			})
		}
	}
}

func TestMieruLowEntropyConfiguration(t *testing.T) {
	option := MieruOption{Name: "config-test", Server: "127.0.0.1", Port: 443, Transport: "TCP", UserName: "user", Password: "password"}
	for _, mode := range []pb.LowEntropyMode{pb.LowEntropyMode_LOW_ENTROPY_MODE_OFF, pb.LowEntropyMode_LOW_ENTROPY_MODE_32, pb.LowEntropyMode_LOW_ENTROPY_MODE_40, pb.LowEntropyMode_LOW_ENTROPY_MODE_48, pb.LowEntropyMode_LOW_ENTROPY_MODE_56} {
		t.Run(mode.String(), func(t *testing.T) {
			pattern := mieruTestPattern(mode)
			option.TrafficPattern = mierutp.Encode(pattern)
			config, err := buildMieruClientConfig(option)
			if err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(config.Profile.TrafficPattern, pattern) {
				t.Fatal("traffic pattern changed during adapter conversion")
			}
		})
	}
	for _, invalid := range []*pb.TrafficPattern{
		{LowEntropy: &pb.LowEntropyPattern{Mode: pb.LowEntropyMode(99).Enum()}},
		{LowEntropy: &pb.LowEntropyPattern{Mode: pb.LowEntropyMode_LOW_ENTROPY_MODE_32.Enum(), MaskRotation: pb.LowEntropyMaskRotation(255).Enum()}},
	} {
		option.TrafficPattern = mierutp.Encode(invalid)
		if _, err := NewMieru(option); err == nil {
			t.Fatal("invalid low entropy configuration accepted")
		}
	}
}
