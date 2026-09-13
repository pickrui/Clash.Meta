package inbound_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/tls"
)

func TestInboundShadowSocks_RestlsTLS12(t *testing.T) { testInboundRestls(t, "tls12") }
func TestInboundShadowSocks_RestlsTLS13(t *testing.T) { testInboundRestls(t, "tls13") }

func testInboundRestls(t *testing.T, version string) {
	options := inbound.ShadowSocksOption{ResTLS: inbound.ResTLS{Enable: true, Dest: net.JoinHostPort(realityDest, "443"), Password: shadowsocksPassword16, RateLimit: 1}}
	client := outbound.ShadowSocksOption{Plugin: "restls", ClientFingerprint: "chrome", PluginOpts: map[string]any{
		"host": realityDest, "password": shadowsocksPassword16, "fingerprint": tlsFingerprint, "version-hint": version, "force-tls12": version == "tls12",
	}}
	// Exercise both sing (including 2022 and mux) and embedded stream ciphers.
	// A one-bit fallback limit must not throttle authenticated proxy traffic.
	testInboundShadowSocks(t, options, client, [][]string{{"none"}, {"chacha20-ietf-poly1305"}, {"2022-blake3-aes-128-gcm"}, {"aes-128-cfb"}}, true)
}

func restlsEchoInbound(t *testing.T, password string) (*inbound.ShadowSocks, *atomic.Int32) {
	t.Helper()
	var delivered atomic.Int32
	tunnel := &TestTunnel{HandleTCPConnFn: func(conn net.Conn, metadata *C.Metadata) {
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if metadata.Type == C.INNER {
			if metadata.Host != realityDest || metadata.SpecialProxy != "camouflage-route" {
				t.Errorf("wrong camouflage route: %v", metadata)
				return
			}
			secured := tls.Server(conn, tlsConfig.Clone())
			defer secured.Close()
			_, _ = io.Copy(secured, secured)
			return
		}
		if metadata.Type != C.SHADOWSOCKS || metadata.InName != "restls-echo" {
			t.Errorf("unexpected proxy metadata: %v", metadata)
			return
		}
		delivered.Add(1)
		_, _ = io.Copy(conn, conn)
	}}
	listener, err := inbound.NewShadowSocks(&inbound.ShadowSocksOption{
		BaseOption: inbound.BaseOption{NameStr: "restls-echo", Listen: "127.0.0.1", Port: "0"},
		Cipher:     "chacha20-ietf-poly1305", Password: shadowsocksPassword16,
		ResTLS: inbound.ResTLS{Enable: true, Dest: net.JoinHostPort(realityDest, "443"), Password: password, Proxy: "camouflage-route"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.Listen(tunnel); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener, &delivered
}

func TestInboundRestlsAuthenticatedConnectionSurvivesClose(t *testing.T) {
	listener, delivered := restlsEchoInbound(t, "restls-password")
	address := netip.MustParseAddrPort(listener.Address())
	proxy, err := outbound.NewShadowSocks(outbound.ShadowSocksOption{Name: "restls", Server: "127.0.0.1", Port: int(address.Port()),
		Cipher: "chacha20-ietf-poly1305", Password: shadowsocksPassword16, Plugin: "restls", ClientFingerprint: "chrome",
		PluginOpts: map[string]any{"host": realityDest, "password": "restls-password", "fingerprint": tlsFingerprint, "version-hint": "tls13"}})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := proxy.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 80})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	for i := range 2 {
		payload := []byte(fmt.Sprintf("authenticated-payload-%d", i))
		if _, err := conn.Write(payload); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, response); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(payload, response) {
			t.Fatal("proxy changed payload")
		}
		if i == 0 {
			if err := listener.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
	if delivered.Load() != 1 {
		t.Fatalf("authenticated streams=%d", delivered.Load())
	}
}

func TestInboundRestlsOrdinaryTLSFallback(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(fmt.Sprintf("tls%x", version), func(t *testing.T) {
			listener, delivered := restlsEchoInbound(t, "restls-password")
			raw, err := net.DialTimeout("tcp", listener.Address(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
			config := tlsClientConfig.Clone()
			config.ServerName = realityDest
			config.MinVersion, config.MaxVersion = version, version
			conn := tls.Client(raw, config)
			defer conn.Close()
			if err := conn.Handshake(); err != nil {
				t.Fatal(err)
			}
			payload := []byte("ordinary TLS reaches only the camouflage target")
			if _, err := conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			response := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, response); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(payload, response) {
				t.Fatal("TLS fallback changed bytes")
			}
			if delivered.Load() != 0 {
				t.Fatal("ordinary TLS was accepted as a proxy")
			}
			if err := listener.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Read(make([]byte, 1)); err == nil {
				t.Fatal("fallback remained open after listener close")
			}
		})
	}
}

func TestInboundRestlsWrongPasswordDoesNotEnterProxy(t *testing.T) {
	listener, delivered := restlsEchoInbound(t, "server-password")
	address := netip.MustParseAddrPort(listener.Address())
	proxy, err := outbound.NewShadowSocks(outbound.ShadowSocksOption{Name: "restls", Server: "127.0.0.1", Port: int(address.Port()),
		Cipher: "chacha20-ietf-poly1305", Password: shadowsocksPassword16, Plugin: "restls",
		PluginOpts: map[string]any{"host": realityDest, "password": "wrong-password", "fingerprint": tlsFingerprint, "version-hint": "tls13"}})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := proxy.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 80})
	if conn != nil {
		defer conn.Close()
	}
	if err == nil {
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		_, writeErr := conn.Write([]byte("not-authenticated"))
		if writeErr == nil {
			// Restls intentionally falls back to ordinary TLS. This echo
			// camouflage target may reflect bytes, but must never proxy them.
			_, _ = conn.Read(make([]byte, 1))
		}
	}
	if delivered.Load() != 0 {
		t.Fatal("wrong password entered the Shadowsocks handler")
	}
}
