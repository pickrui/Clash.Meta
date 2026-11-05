package restls

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	R "github.com/metacubex/mihomo/transport/restls"
	"github.com/metacubex/mihomo/transport/vmess"
	"github.com/metacubex/tls"
)

func TestListenerClosePendingHandshakes(t *testing.T) {
	const count = 12
	opened := make(chan struct{}, count)
	closed := make(chan struct{}, count)
	tunnel := &localTunnel{handle: func(conn net.Conn, _ *C.Metadata) {
		defer conn.Close()
		defer func() { closed <- struct{}{} }()
		opened <- struct{}{}
		_, _ = io.Copy(io.Discard, conn)
	}}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l, err := NewListener(raw, LC.ResTLS{Dest: "camouflage.test", Password: "password"}, tunnel)
	if err != nil {
		raw.Close()
		t.Fatal(err)
	}
	defer l.Close()
	for range count {
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		select {
		case <-opened:
		case <-time.After(3 * time.Second):
			t.Fatal("handshakes did not run concurrently")
		}
	}
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			if err := l.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	for range count {
		select {
		case <-closed:
		case <-time.After(3 * time.Second):
			t.Fatal("camouflage target leaked on close")
		}
	}
	if c, err := l.Accept(); c != nil || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after Close: %v, %v", c, err)
	}
}

func TestListenerAuthenticatedHandoff(t *testing.T) {
	certPEM, keyPEM, pin, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"tls12", "tls13"} {
		for _, handoff := range []bool{false, true} {
			name := "unclaimed"
			if handoff {
				name = "accepted"
			}
			t.Run(version+"/"+name, func(t *testing.T) {
				targetConfig := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
				if version == "tls12" {
					targetConfig.MinVersion = tls.VersionTLS12
					targetConfig.MaxVersion = tls.VersionTLS12
				}
				tunnel := &localTunnel{handle: func(conn net.Conn, _ *C.Metadata) {
					defer conn.Close()
					secured := tls.Server(conn, targetConfig)
					defer secured.Close()
					_, _ = io.Copy(io.Discard, secured)
				}}
				raw, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				l, err := NewListener(raw, LC.ResTLS{Dest: "camouflage.test", Password: "password"}, tunnel)
				if err != nil {
					raw.Close()
					t.Fatal(err)
				}
				defer l.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				wire, err := (&net.Dialer{}).DialContext(ctx, "tcp", l.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer wire.Close()
				_ = wire.SetDeadline(time.Now().Add(5 * time.Second))
				base, err := R.NewRestlsConfig("original.test", "password", version, "", "firefox")
				if err != nil {
					t.Fatal(err)
				}
				base.ForceTLS12 = version == "tls12"
				client, err := vmess.StreamTLSConn(ctx, wire, &vmess.TLSConfig{Host: "camouflage.test", NextProtos: []string{"h2"}, FingerPrint: pin, Restls: base})
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				if base.ServerName != "original.test" || len(base.NextProtos) != 0 || base.VerifyConnection != nil || base.InsecureSkipVerify {
					t.Fatal("shared TLS wrapper mutated reusable Restls options")
				}
				if !handoff {
					l.Close()
					_, err = client.Read(make([]byte, 1))
					if err == nil {
						t.Fatal("unclaimed authenticated session survived close")
					}
					if e, ok := err.(net.Error); ok && e.Timeout() {
						t.Fatal("unclaimed handoff leaked")
					}
					return
				}
				accepted := make(chan net.Conn, 1)
				go func() {
					c, e := l.Accept()
					if e == nil {
						accepted <- c
					}
				}()
				// The Restls server authenticates the first application record before handoff.
				written := make(chan error, 1)
				go func() { _, e := io.WriteString(client, "before-close"); written <- e }()
				var server net.Conn
				select {
				case server = <-accepted:
				case <-ctx.Done():
					t.Fatal("authenticated handoff blocked")
				}
				defer server.Close()
				done := make(chan struct{})
				go func() { defer close(done); _, _ = io.Copy(server, server) }()
				response := make([]byte, len("before-close"))
				if _, err := io.ReadFull(client, response); err != nil {
					t.Fatal(err)
				}
				if err := <-written; err != nil {
					t.Fatal(err)
				}
				if string(response) != "before-close" {
					t.Fatal("changed payload")
				}
				l.Close()
				if _, err := io.WriteString(client, "after-close!"); err != nil {
					t.Fatal(err)
				}
				if _, err := io.ReadFull(client, response); err != nil {
					t.Fatal(err)
				}
				if string(response) != "after-close!" {
					t.Fatal("listener close damaged established session")
				}
				client.Close()
				server.Close()
				select {
				case <-done:
				case <-ctx.Done():
					t.Fatal("established session did not release")
				}
			})
		}
	}
}
