package outbound

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	mux "github.com/metacubex/sing-mux"
	SB "github.com/metacubex/sing/common/bufio"
	"github.com/metacubex/sing/common/logger"
	M "github.com/metacubex/sing/common/metadata"
	SN "github.com/metacubex/sing/common/network"
)

type muxTestDialer struct{ conn net.Conn }

func (d muxTestDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return d.conn, nil
}
func (d muxTestDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unexpected UDP dial")
}

type muxTestHandler struct{ packets chan SN.NetPacketConn }

func (h muxTestHandler) NewConnection(context.Context, net.Conn, M.Metadata) error {
	return errors.New("unexpected TCP stream")
}
func (h muxTestHandler) NewPacketConnection(ctx context.Context, conn SN.PacketConn, _ M.Metadata) error {
	select {
	case h.packets <- SB.NewNetPacketConn(conn):
	case <-ctx.Done():
		return ctx.Err()
	}
	<-ctx.Done()
	return nil
}

func TestSingMuxConcurrentDatagrams(t *testing.T) {
	for _, protocol := range []string{"smux", "yamux", "h2mux"} {
		for _, packetAddr := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/address=%t", protocol, packetAddr), func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				left, right := net.Pipe()
				handler := muxTestHandler{packets: make(chan SN.NetPacketConn, 1)}
				service, err := mux.NewService(mux.ServiceOptions{Handler: handler, Logger: logger.NOP(), NewStreamContext: func(ctx context.Context, _ net.Conn) context.Context { return ctx }})
				if err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() { done <- service.NewConnection(ctx, right, M.Metadata{}) }()
				client, err := mux.NewClient(mux.Options{Dialer: muxTestDialer{left}, Protocol: protocol, Logger: logger.NOP(), MaxConnections: 1})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					cancel()
					_ = client.Close()
					_ = left.Close()
					_ = right.Close()
					select {
					case <-done:
					case <-time.After(3 * time.Second):
						t.Error("mux service did not stop")
					}
				})
				dest := M.ParseSocksaddr("192.0.2.1:5353")
				var clientPC net.PacketConn
				if packetAddr {
					clientPC, err = client.ListenPacket(ctx, dest)
				} else {
					var conn net.Conn
					conn, err = client.DialContext(ctx, "udp", dest)
					if err == nil {
						clientPC = conn.(net.PacketConn)
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				defer clientPC.Close()
				_ = clientPC.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err = clientPC.WriteTo([]byte("seed"), dest.UDPAddr()); err != nil {
					t.Fatal(err)
				}
				var serverPC SN.NetPacketConn
				select {
				case serverPC = <-handler.packets:
				case <-time.After(5 * time.Second):
					t.Fatal("missing mux packet stream")
				}
				_ = serverPC.SetDeadline(time.Now().Add(5 * time.Second))
				data := make([]byte, 64)
				if n, _, err := serverPC.ReadFrom(data); err != nil || string(data[:n]) != "seed" {
					t.Fatalf("request handshake: %q %v", data[:n], err)
				}
				if _, err = serverPC.WriteTo([]byte("ready"), dest.UDPAddr()); err != nil {
					t.Fatal(err)
				}
				if n, _, err := clientPC.ReadFrom(data); err != nil || string(data[:n]) != "ready" {
					t.Fatalf("response handshake: %q %v", data[:n], err)
				}
				for _, direction := range []struct {
					name           string
					writer, reader net.PacketConn
				}{{"client", clientPC, serverPC}, {"server", serverPC, clientPC}} {
					if err := checkMuxDatagrams(direction.writer, direction.reader, dest.UDPAddr(), packetAddr); err != nil {
						t.Fatalf("%s writes: %v", direction.name, err)
					}
				}
			})
		}
	}
}

func checkMuxDatagrams(writer, reader net.PacketConn, destination net.Addr, packetAddr bool) error {
	const workers = 12
	const perWorker = 12
	deadline := time.Now().Add(5 * time.Second)
	_ = writer.SetDeadline(deadline)
	_ = reader.SetDeadline(deadline)
	var group sync.WaitGroup
	failures := make(chan error, workers)
	start := make(chan struct{})
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func(worker int) {
			defer group.Done()
			<-start
			for i := 0; i < perWorker; i++ {
				id := worker*perWorker + i
				payload := bytes.Repeat([]byte{byte(id)}, 64+id%31)
				binary.BigEndian.PutUint32(payload, uint32(id))
				n, err := writer.WriteTo(payload, destination)
				if err != nil || n != len(payload) {
					failures <- fmt.Errorf("write %d: %d, %v", id, n, err)
					return
				}
				runtime.Gosched()
			}
		}(worker)
	}
	close(start)
	var result error
	seen := make(map[uint32]bool)
	for i := 0; i < workers*perWorker; i++ {
		payload := make([]byte, 2048)
		n, addr, err := reader.ReadFrom(payload)
		if err != nil {
			result = fmt.Errorf("read %d: %w", i, err)
			break
		}
		if n < 4 {
			result = fmt.Errorf("short datagram: %d", n)
			break
		}
		id := binary.BigEndian.Uint32(payload)
		if id >= workers*perWorker || seen[id] || n != 64+int(id)%31 || (packetAddr && (addr == nil || addr.String() != destination.String())) || !bytes.Equal(payload[4:n], bytes.Repeat([]byte{byte(id)}, n-4)) {
			result = fmt.Errorf("corrupted or repeated datagram: id=%d length=%d address=%v", id, n, addr)
			break
		}
		seen[id] = true
	}
	if result != nil {
		_ = writer.Close()
		_ = reader.Close()
	}
	group.Wait()
	close(failures)
	for err := range failures {
		result = errors.Join(result, err)
	}
	return result
}
