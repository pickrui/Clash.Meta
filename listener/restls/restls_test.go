package restls

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
)

type localTunnel struct {
	C.Tunnel
	handle func(net.Conn, *C.Metadata)
}

func (t *localTunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) { t.handle(conn, metadata) }

func TestServerOptions(t *testing.T) {
	config := LC.ResTLS{Dest: "camouflage.test:443", Password: "test", RestlsScript: "300?100<1,400~100", MinRecordLen: 32, RateLimit: 65536, Proxy: "test-chain"}
	server, err := New(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if server.config.ServerHostname != config.Dest || server.config.Password != config.Password || server.config.RestlsScript != config.RestlsScript || server.config.MinRecordLen != 32 || server.config.RateLimit != 65536 {
		t.Fatal("server options changed")
	}
	for _, test := range []struct{ name, dest, script string }{
		{"missing_destination", "", ""}, {"blank_destination", " ", ""}, {"invalid_script", "camouflage.test", "40000"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := New(LC.ResTLS{Dest: test.dest, RestlsScript: test.script}, nil); err == nil {
				t.Fatal("invalid server configuration accepted")
			}
		})
	}
}

func TestServerClosePendingConnections(t *testing.T) {
	const attempts = 12
	targets := make(chan *C.Metadata, attempts)
	targetsClosed := make(chan struct{}, attempts)
	tunnel := &localTunnel{handle: func(conn net.Conn, metadata *C.Metadata) {
		defer conn.Close()
		defer func() { targetsClosed <- struct{}{} }()
		targets <- metadata
		_, _ = io.Copy(io.Discard, conn)
	}}
	server, err := New(LC.ResTLS{Dest: "camouflage.test", Password: "test", Proxy: "test-chain"}, tunnel)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	done := make(chan error, attempts)
	for range attempts {
		client, peer := net.Pipe()
		t.Cleanup(func() { client.Close() })
		go func() {
			conn, err := server.WrapConn(peer)
			if conn != nil {
				conn.Close()
				done <- io.ErrUnexpectedEOF
				return
			}
			done <- err
		}()
	}
	for range attempts {
		select {
		case metadata := <-targets:
			if metadata.Type != C.INNER || metadata.Host != "camouflage.test" || metadata.DstPort != 443 || metadata.SpecialProxy != "test-chain" {
				t.Errorf("wrong fallback metadata: %v", metadata)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("target was not opened")
		}
	}
	server.Close()
	server.Close()
	for range attempts {
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("closed handshake succeeded")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("handshake remained blocked after Close")
		}
		select {
		case <-targetsClosed:
		case <-time.After(3 * time.Second):
			t.Fatal("camouflage target remained open")
		}
	}
	client, peer := net.Pipe()
	defer client.Close()
	if conn, err := server.WrapConn(peer); err != net.ErrClosed || conn != nil {
		t.Fatalf("post-close handshake: conn=%v err=%v", conn, err)
	}
}

func TestServerPlainFallbackAndRateLimit(t *testing.T) {
	for _, rate := range []uint64{0, 32768} {
		name := "unlimited"
		if rate != 0 {
			name = "limited"
		}
		t.Run(name, func(t *testing.T) {
			targetClosed := make(chan struct{})
			tunnel := &localTunnel{handle: func(conn net.Conn, _ *C.Metadata) {
				defer close(targetClosed)
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}}
			server, err := New(LC.ResTLS{Dest: "camouflage.test", Password: "test", RateLimit: rate}, tunnel)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			client, peer := net.Pipe()
			defer client.Close()
			_ = client.SetDeadline(time.Now().Add(5 * time.Second))
			done := make(chan error, 1)
			go func() {
				conn, err := server.WrapConn(peer)
				if conn != nil {
					conn.Close()
					done <- io.ErrUnexpectedEOF
					return
				}
				done <- err
			}()
			payload := "GET / HTTP/1.0\r\n\r\n" + strings.Repeat("x", 4096)
			written := make(chan error, 1)
			start := time.Now()
			go func() { _, err := io.WriteString(client, payload); written <- err }()
			response := make([]byte, len(payload))
			if _, err := io.ReadFull(client, response); err != nil {
				t.Fatal(err)
			}
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			if string(response) != payload {
				t.Fatal("fallback changed plain bytes")
			}
			if rate != 0 && time.Since(start) < 500*time.Millisecond {
				t.Fatal("fallback rate limit was not applied")
			}
			server.Close()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("fallback was returned as authenticated")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("fallback did not close")
			}
			select {
			case <-targetClosed:
			case <-time.After(3 * time.Second):
				t.Fatal("fallback target leaked")
			}
		})
	}
}

func TestServerCloseCancelsFallbackRateWait(t *testing.T) {
	tunnel := &localTunnel{handle: func(conn net.Conn, _ *C.Metadata) {
		defer conn.Close()
		sent := make(chan struct{})
		go func() { defer close(sent); _, _ = io.WriteString(conn, "fallback-response") }()
		_, _ = io.Copy(io.Discard, conn)
		_ = conn.Close()
		<-sent
	}}
	server, err := New(LC.ResTLS{Dest: "camouflage.test", Password: "test", RateLimit: 1}, tunnel)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, peer := net.Pipe()
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan error, 1)
	go func() { _, err := server.WrapConn(peer); done <- err }()
	written := make(chan struct{})
	go func() { defer close(written); _, _ = io.WriteString(client, "GET / HTTP/1.0\r\n\r\n") }()
	// The first fallback byte is free; subsequent one-byte reservations at
	// one bit/second wait eight seconds unless Close cancels the limiter.
	if _, err := io.ReadFull(client, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	server.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close waited for the fallback rate interval")
	}
	<-written
}
