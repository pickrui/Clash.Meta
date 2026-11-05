package outbound

import (
	"context"
	"errors"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/sing-quic/hysteria2"
)

func TestHysteria2CloseReleasesRealmIdleConnection(t *testing.T) {
	closed := make(chan struct{}, 1)
	server := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.WriteHeader(stdhttp.StatusNoContent)
	}))
	server.Config.ConnState = func(_ net.Conn, state stdhttp.ConnState) {
		if state == stdhttp.StateClosed {
			closed <- struct{}{}
		}
	}
	server.Start()
	defer server.Close()
	client, err := NewHysteria2(Hysteria2Option{
		Server: "127.0.0.1", Port: 443,
		RealmOpts: Hysteria2RealmOption{Enable: true, ServerURL: server.URL},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	response, err := (&http.Client{Transport: client.realmTransport, Timeout: time.Second}).Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	select {
	case <-closed:
		t.Fatal("control connection was already closed before closing the outbound")
	default:
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("realm control connection remained idle after close")
	}
}

func TestHysteria2LazyClientLifecycle(t *testing.T) {
	client, err := NewHysteria2(Hysteria2Option{Server: "127.0.0.1", Ports: "1-65535"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if client.client != nil {
		t.Fatal("unused hopping node allocated its client")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.lazyClient(ctx); !errors.Is(err, context.Canceled) || client.client != nil {
		t.Fatalf("canceled request initialized a client: %v", err)
	}
	clients := make(chan *hysteria2.Client, 32)
	var wg sync.WaitGroup
	for range cap(clients) {
		wg.Go(func() {
			c, err := client.lazyClient(context.Background())
			if err != nil {
				t.Error(err)
			}
			clients <- c
		})
	}
	wg.Wait()
	close(clients)
	for c := range clients {
		if c == nil || c != client.client {
			t.Fatal("concurrent requests did not share one client")
		}
	}
	if client.buildClient != nil {
		t.Fatal("initialized client retained its pending configuration")
	}
	_ = client.Close()
	if _, err := client.lazyClient(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("initialized client reopened after close: %v", err)
	}
}

func TestHysteria2PortExpansion(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  []uint16
	}{
		{"*", nil}, {"/", nil}, {"0", []uint16{0}},
		{"443/445-443/65534-65535,0", []uint16{443, 443, 444, 445, 65534, 65535, 0}},
	} {
		t.Run(tc.input, func(t *testing.T) {
			ranges, err := utils.NewUnsignedRanges[uint16](tc.input)
			if err != nil {
				t.Fatal(err)
			}
			ports := expandHysteria2Ports(ranges)
			if !slices.Equal(ports, tc.want) {
				t.Fatalf("ports = %v, want %v", ports, tc.want)
			}
		})
	}
	ranges, err := utils.NewUnsignedRanges[uint16]("0-65535")
	if err != nil {
		t.Fatal(err)
	}
	ports := expandHysteria2Ports(ranges)
	if len(ports) != 65536 || cap(ports) != len(ports) || ports[0] != 0 || ports[len(ports)-1] != 65535 {
		t.Fatal("full port range overflowed or grew beyond its final size")
	}
}

func TestHysteria2CloseIsTerminal(t *testing.T) {
	for _, tc := range []struct{ network, ports string }{
		{"tcp", ""}, {"udp", ""}, {"tcp", "40000-50000"}, {"udp", "40000-50000"},
	} {
		t.Run(tc.network+"/"+tc.ports, func(t *testing.T) {
			client, err := NewHysteria2(Hysteria2Option{Server: "127.0.0.1", Port: 443, Ports: tc.ports})
			if err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if err := client.Close(); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			metadata := &C.Metadata{DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: 443}
			if tc.network == "tcp" {
				conn, dialErr := client.DialContext(ctx, metadata)
				err = dialErr
				if conn != nil {
					_ = conn.Close()
				}
			} else {
				conn, dialErr := client.ListenPacketContext(ctx, metadata)
				err = dialErr
				if conn != nil {
					_ = conn.Close()
				}
			}
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("request after close: %v", err)
			}
		})
	}
}

func TestHysteria2CloseCancelsHandshake(t *testing.T) {
	for _, seconds := range []int{0, 30} {
		t.Run(strconv.Itoa(seconds), func(t *testing.T) {
			peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			client, err := NewHysteria2(Hysteria2Option{
				Server: "127.0.0.1", Port: peer.LocalAddr().(*net.UDPAddr).Port, HandshakeTimeout: seconds,
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			defer client.Close()
			result := make(chan error, 1)
			go func() {
				conn, err := client.DialContext(ctx, &C.Metadata{Host: "example.test", DstPort: 443})
				if conn != nil {
					_ = conn.Close()
				}
				result <- err
			}()
			_ = peer.SetReadDeadline(time.Now().Add(3 * time.Second))
			if _, _, err := peer.ReadFrom(make([]byte, 2048)); err != nil {
				cancel()
				t.Fatal(err)
			}
			closed := make(chan error, 1)
			go func() { closed <- client.Close() }()
			select {
			case err := <-closed:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(time.Second):
				t.Error("close blocked on a pending handshake")
				cancel()
				<-closed
			}
			select {
			case err := <-result:
				if err == nil {
					t.Error("handshake succeeded after close")
				}
			case <-time.After(time.Second):
				cancel()
				t.Fatal("close left the handshake running")
			}
		})
	}
}

func TestHysteria2RejectsInvalidConfigAtLoad(t *testing.T) {
	for _, tc := range []struct {
		name   string
		modify func(*Hysteria2Option)
		want   string
	}{
		{"port", func(o *Hysteria2Option) { o.Port = 0 }, "invalid port"},
		{"ports", func(o *Hysteria2Option) { o.Ports = "invalid" }, "invalid range"},
		{"hop interval", func(o *Hysteria2Option) { o.Ports, o.HopInterval = "40000-50000", "invalid" }, "invalid range"},
		{"obfs password", func(o *Hysteria2Option) { o.Obfs = "salamander" }, "missing obfs password"},
		{"obfs type", func(o *Hysteria2Option) { o.Obfs, o.ObfsPassword = "unknown", "test" }, "unknown obfs type"},
		{"gecko bounds", func(o *Hysteria2Option) { o.Obfs, o.ObfsPassword, o.ObfsMaxPacketSize = "gecko", "test", 2049 }, "gecko: invalid packet size range"},
		{"fingerprint", func(o *Hysteria2Option) { o.Fingerprint = "invalid" }, "fingerprint"},
		{"certificate", func(o *Hysteria2Option) { o.Certificate, o.PrivateKey = "invalid", "invalid" }, "parse certificate failed"},
		{"ech", func(o *Hysteria2Option) { o.ECHOpts = ECHOptions{Enable: true, Config: "invalid"} }, "base64"},
		{"realm url", func(o *Hysteria2Option) { o.RealmOpts.Enable = true }, "control server URL is required"},
		{"realm ports", func(o *Hysteria2Option) { o.RealmOpts.Enable, o.Ports = true, "1-65535" }, "realm and port hopping are mutually exclusive"},
		{"realm fingerprint", func(o *Hysteria2Option) { o.RealmOpts.Enable, o.RealmOpts.Fingerprint = true, "invalid" }, "fingerprint"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			option := Hysteria2Option{Server: "127.0.0.1", Port: 443}
			tc.modify(&option)
			client, err := NewHysteria2(option)
			if client != nil {
				_ = client.Close()
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("constructor error = %v, want %q", err, tc.want)
			}
		})
	}
}

func BenchmarkHysteria2Unused(b *testing.B) {
	for _, tc := range []struct{ name, ports string }{
		{"plain", ""}, {"10001_ports", "40000-50000"}, {"65535_ports", "1-65535"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			option := Hysteria2Option{Server: "127.0.0.1", Port: 443, Ports: tc.ports}
			warm, err := NewHysteria2(option)
			if err != nil {
				b.Fatal(err)
			}
			_ = warm.Close()
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				client, err := NewHysteria2(option)
				if err != nil {
					b.Fatal(err)
				}
				_ = client.Close()
			}
		})
	}
}
