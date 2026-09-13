package common

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/transport/tuic/internal/testutil"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	qtls "github.com/metacubex/sing-quic"
	"github.com/metacubex/sing-quic/hysteria2"
	"github.com/metacubex/sing/common/logger"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/tls"
)

// Only authentication and stream admission are needed here. The peer never
// forwards traffic, and its small receive window deliberately blocks writers.
type hysteria2Peer struct {
	options     hysteria2.ClientOptions
	auth        chan struct{}
	streams     chan *quic.Stream
	connections chan *quic.Conn
	packets     chan *capturePacketConn
	dials       atomic.Int32
}

func newHysteria2Peer(t *testing.T, authGate <-chan struct{}) *hysteria2Peer {
	t.Helper()
	serverTLS, clientTLS := testutil.TLSConfigs(t)
	serverTLS.NextProtos = []string{http3.NextProtoH3}
	clientTLS.NextProtos = []string{http3.NextProtoH3}
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	p := &hysteria2Peer{auth: make(chan struct{}, 16), streams: make(chan *quic.Stream, 16), connections: make(chan *quic.Conn, 16), packets: make(chan *capturePacketConn, 16)}
	server := &http3.Server{
		TLSConfig:       serverTLS,
		QUICConfig:      &quic.Config{InitialStreamReceiveWindow: 1024, MaxStreamReceiveWindow: 1024, EnableDatagrams: true},
		EnableDatagrams: true,
		ConnContext:     func(ctx context.Context, conn *quic.Conn) context.Context { p.connections <- conn; return ctx },
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != "/auth" || r.Header.Get("Hysteria-Auth") != "test-password" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			p.auth <- struct{}{}
			if authGate != nil {
				select {
				case <-authGate:
				case <-r.Context().Done():
					return
				}
			}
			w.Header().Set("Hysteria-UDP", "true")
			w.Header().Set("Hysteria-CC-RX", "auto")
			w.WriteHeader(233)
		}),
		StreamDispatcher: func(frame http3.FrameType, stream *quic.Stream, err error) (bool, error) {
			if err != nil || frame != 0x401 {
				return false, nil
			}
			p.streams <- stream
			return true, nil
		},
	}
	served := make(chan error, 1)
	go func() { served <- server.Serve(pc) }()
	t.Cleanup(func() { _ = server.Close(); <-served })
	p.options = hysteria2.ClientOptions{
		Context: context.Background(), Logger: logger.NOP(), Password: "test-password",
		TLSConfig: clientTLS, ServerAddress: M.SocksaddrFromNet(pc.LocalAddr()),
		QuicDialer: qtls.QuicDialerFunc(func(ctx context.Context, addr string, _ qtls.PacketDialer, tlsCfg *tls.Config, cfg *quic.Config, early bool) (net.PacketConn, *quic.Conn, error) {
			p.dials.Add(1)
			d := &loopbackPacketDialer{}
			pc, conn, err := DialQuic(ctx, addr, nil, d, tlsCfg, cfg, DialQuicOption{Early: early})
			if d.conn != nil {
				p.packets <- d.conn
			}
			return pc, conn, err
		}),
	}
	return p
}

func newHysteria2Client(t *testing.T, options hysteria2.ClientOptions) *hysteria2.Client {
	t.Helper()
	client, err := hysteria2.NewClient(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.CloseWithError(net.ErrClosed) })
	return client
}

func awaitHysteria2[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for Hysteria2 operation")
	}
	var zero T
	return zero
}

func TestHysteria2CloseUnblocksFlowControlledWrite(t *testing.T) {
	p := newHysteria2Peer(t, nil)
	client := newHysteria2Client(t, p.options)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := client.DialConn(ctx, M.ParseSocksaddr("example.test:443"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	written := make(chan error, 1)
	go func() { _, err := conn.Write(make([]byte, 1<<20)); written <- err }()
	_ = awaitHysteria2(t, p.streams)
	select {
	case err := <-written:
		t.Fatalf("write finished before close: %v", err)
	default:
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-written:
		if err == nil {
			t.Fatal("blocked write returned success after close")
		}
	case <-time.After(time.Second):
		_ = conn.SetWriteDeadline(time.Now())
		_ = awaitHysteria2(t, written)
		t.Fatal("closing the stream left its flow-controlled writer blocked")
	}
}

func TestHysteria2TCPOnlyPeerCloseReleasesPacketConn(t *testing.T) {
	p := newHysteria2Peer(t, nil)
	p.options.UDPDisabled = true
	client := newHysteria2Client(t, p.options)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := client.DialConn(ctx, M.ParseSocksaddr("example.test:443"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	serverConn := awaitHysteria2(t, p.connections)
	packetConn := awaitHysteria2(t, p.packets)
	_ = serverConn.CloseWithError(0, "peer shutdown")
	select {
	case <-packetConn.closed:
	case <-time.After(time.Second):
		t.Fatal("peer shutdown leaked the client UDP socket when UDP relay is disabled")
	}
}

func TestHysteria2SharedHandshakeSurvivesCallerCancellation(t *testing.T) {
	gate := make(chan struct{})
	p := newHysteria2Peer(t, gate)
	p.options.HandshakeTimeout = 3 * time.Second
	client := newHysteria2Client(t, p.options)
	firstCtx, cancelFirst := context.WithCancel(context.Background())
	defer cancelFirst()
	first := make(chan error, 1)
	go func() {
		conn, err := client.DialConn(firstCtx, M.ParseSocksaddr("example.test:443"))
		if conn != nil {
			_ = conn.Close()
		}
		first <- err
	}()
	_ = awaitHysteria2(t, p.auth)
	cancelFirst()
	if err := awaitHysteria2(t, first); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled caller: %v", err)
	}
	// All callers join the background offer, then reuse its authenticated QUIC connection.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	results := make(chan error, 8)
	for range cap(results) {
		go func() {
			conn, err := client.DialConn(ctx, M.ParseSocksaddr("example.test:443"))
			if conn != nil {
				_ = conn.Close()
			}
			results <- err
		}()
	}
	close(gate)
	for range cap(results) {
		if err := awaitHysteria2(t, results); err != nil {
			t.Fatal(err)
		}
	}
	if got := p.dials.Load(); got != 1 {
		t.Fatalf("shared handshake dialed %d times", got)
	}
}

func TestHysteria2DefaultHandshakeFollowsCaller(t *testing.T) {
	p := newHysteria2Peer(t, make(chan struct{}))
	client := newHysteria2Client(t, p.options)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := client.DialConn(ctx, M.ParseSocksaddr("example.test:443")); result <- err }()
	_ = awaitHysteria2(t, p.auth)
	packet := awaitHysteria2(t, p.packets)
	cancel()
	if err := awaitHysteria2(t, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled handshake: %v", err)
	}
	_ = awaitHysteria2(t, packet.closed)
}

func TestHysteria2IndependentHandshakeDeadlineAndRetry(t *testing.T) {
	for _, mode := range []string{"deadline", "close", "lifetime"} {
		t.Run(mode, func(t *testing.T) {
			lifetime, cancelLifetime := context.WithCancel(context.Background())
			defer cancelLifetime()
			entered := make(chan context.Context, 2)
			var dials atomic.Int32
			retryErr := errors.New("retry reached dialer")
			options := hysteria2.ClientOptions{
				Context: lifetime, Logger: logger.NOP(), TLSConfig: &tls.Config{},
				HandshakeTimeout: 100 * time.Millisecond,
				QuicDialer: qtls.QuicDialerFunc(func(ctx context.Context, _ string, _ qtls.PacketDialer, _ *tls.Config, _ *quic.Config, _ bool) (net.PacketConn, *quic.Conn, error) {
					if dials.Add(1) > 1 {
						return nil, nil, retryErr
					}
					entered <- ctx
					<-ctx.Done()
					return nil, nil, context.Cause(ctx)
				}),
			}
			if mode != "deadline" {
				options.HandshakeTimeout = 3 * time.Second
			}
			client := newHysteria2Client(t, options)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() { _, err := client.DialConn(ctx, M.ParseSocksaddr("example.test:443")); result <- err }()
			offerCtx := awaitHysteria2(t, entered)
			want := error(context.DeadlineExceeded)
			switch mode {
			case "close":
				want = errors.New("proxy removed during handshake")
				if err := client.CloseWithError(want); err != nil {
					t.Fatal(err)
				}
			case "lifetime":
				want = context.Canceled
				cancelLifetime()
			}
			if err := awaitHysteria2(t, result); !errors.Is(err, want) {
				t.Fatalf("handshake ended with %v, want %v", err, want)
			}
			if ctx.Err() != nil {
				t.Fatal("handshake used caller deadline instead of its own cancellation")
			}
			_ = awaitHysteria2(t, offerCtx.Done())
			if mode != "lifetime" {
				_, err := client.DialConn(ctx, M.ParseSocksaddr("example.test:443"))
				if !errors.Is(err, retryErr) {
					t.Fatalf("failed offer was retained instead of retrying: %v", err)
				}
			}
		})
	}
}
