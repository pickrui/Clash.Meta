package outbound

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ech"
	tlsC "github.com/metacubex/mihomo/component/tls"

	"github.com/metacubex/tls"
)

func TestSnellECHTLSUsesRawTLSWithoutPath(t *testing.T) {
	echConfig, _, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}

	adapter, err := NewSnell(SnellOption{
		Name:    "snell",
		Server:  "origin.example.com",
		Port:    443,
		Psk:     "password",
		Version: 4,
		ObfsOpts: map[string]any{
			"mode":       "ech-tls",
			"ech-config": echConfig,
		},
	})
	if err != nil {
		t.Fatalf("NewSnell() error = %v", err)
	}
	defer adapter.Close()

	if adapter.echTLS == nil || adapter.echTLS.ECH == nil {
		t.Fatal("ECH TLS config was not initialized")
	}
	if adapter.echTLS.ClientSessionCache == nil || adapter.echTLS.UClientSessionCache == nil {
		t.Fatal("ECH TLS session caches were not initialized")
	}
	if len(adapter.echTLS.NextProtos) != 1 || adapter.echTLS.NextProtos[0] != snellECHTLSALPN {
		t.Fatalf("NextProtos = %q, want [%q]", adapter.echTLS.NextProtos, snellECHTLSALPN)
	}
}

func TestSnellECHTLSResolvesClientFingerprint(t *testing.T) {
	echConfig, _, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		obfs string
		top  string
		want string
	}{
		{name: "obfs none", obfs: "none", want: defaultSnellClientFingerprint},
		{name: "proxy none", top: "NONE", want: defaultSnellClientFingerprint},
		{name: "explicit", obfs: "firefox", want: "firefox"},
		{name: "case", top: "FireFox120", want: "firefox120"},
		{name: "without ech", obfs: "safari", want: defaultSnellClientFingerprint},
		{name: "unknown", obfs: "chrome131", want: defaultSnellClientFingerprint},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obfs := map[string]any{"mode": "ech-tls", "ech-config": echConfig}
			if tc.obfs != "" {
				obfs["client-fingerprint"] = tc.obfs
			}
			adapter, err := NewSnell(SnellOption{
				Name: "snell", Server: "origin.example.com", Port: 443, Psk: "password", Version: 4,
				ClientFingerprint: tc.top, ObfsOpts: obfs,
			})
			if err != nil {
				t.Fatalf("NewSnell() error = %v", err)
			}
			defer adapter.Close()
			if got := adapter.echTLS.ClientFingerprint; got != tc.want {
				t.Fatalf("ClientFingerprint = %q, want %q", got, tc.want)
			}
		})
	}
}

// clientBytesRecorder keeps what a server reads from its client.
type clientBytesRecorder struct {
	net.Conn
	read []byte
}

func (c *clientBytesRecorder) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.read = append(c.read, b[:n]...)
	return n, err
}

func TestSnellECHTLSFingerprintsKeepALPNPrivate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{"origin.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	echConfig, echKeyPEM, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(echKeyPEM))
	echKeys, err := ech.UnmarshalECHKeys(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := &tls.Config{
		NextProtos: []string{snellECHTLSALPN}, MinVersion: tls.VersionTLS13,
		Certificates:             []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		EncryptedClientHelloKeys: echKeys,
	}
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	// Every name in component/tls's fingerprint table, then none, a wrong case and an unknown name.
	for _, fingerprint := range []string{
		"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random",
		"chrome120", "firefox120", "safari16", "chrome_psk", "chrome_psk_shuffle",
		"chrome_padding_psk_shuffle", "chrome_pq", "chrome_pq_psk", "randomized",
		"none", "Chrome", "chrome131",
	} {
		t.Run(fingerprint, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			hello := make(chan []byte, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					hello <- nil
					return
				}
				defer conn.Close()
				recorder := &clientBytesRecorder{Conn: conn}
				server := tls.Server(recorder, serverConfig)
				_ = server.SetDeadline(time.Now().Add(5 * time.Second))
				_ = server.Handshake()
				hello <- bytes.Clone(recorder.read)
				_, _ = io.Copy(io.Discard, server)
			}()

			adapter, err := NewSnell(SnellOption{
				Name: "snell", Server: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port, Psk: "password", Version: 4,
				ObfsOpts: map[string]any{
					"mode": "ech-tls", "ech-config": echConfig, "sni": "origin.example.com",
					"ca-file": caPEM, "client-fingerprint": fingerprint,
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer adapter.Close()
			used := adapter.echTLS.ClientFingerprint
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := adapter.dialSnellTransport(ctx)
			if err != nil {
				t.Fatalf("handshake with %s: %v", used, err)
			}
			defer conn.Close()
			if state := tlsC.GetTLSConnectionState(conn); !state.ECHAccepted || state.NegotiatedProtocol != snellECHTLSALPN {
				t.Fatalf("%s: ECH accepted %v, ALPN %q", used, state.ECHAccepted, state.NegotiatedProtocol)
			}
			select {
			case raw := <-hello:
				for _, private := range []string{snellECHTLSALPN, "origin.example.com"} {
					if bytes.Contains(raw, []byte(private)) {
						t.Fatalf("%s sends %s in the clear", used, private)
					}
				}
			case <-time.After(5 * time.Second):
				t.Fatal("server handshake did not finish")
			}
		})
	}
}

func TestSnellECHTLSRejectsSkippedCertificateVerification(t *testing.T) {
	echConfig, _, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewSnell(SnellOption{
		Name: "snell", Server: "origin.example.com", Port: 443, Psk: "password", Version: 4,
		ObfsOpts: map[string]any{
			"mode": "ech-tls", "ech-config": echConfig, "skip-cert-verify": true,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "requires certificate verification") {
		t.Fatalf("NewSnell() error = %v", err)
	}
}

func TestSnellECHTLSLegacyFallbackMustBeExplicit(t *testing.T) {
	echConfig, _, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewSnell(SnellOption{
		Name: "snell", Server: "origin.example.com", Port: 443, Psk: "password", Version: 4,
		ObfsOpts: map[string]any{
			"mode": "ech-tls", "alpn": snellECHTLSALPN,
			"identity-version": 2, "legacy-fallback": true, "ech-config": echConfig,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	if got := adapter.echTLS.NextProtos; len(got) != 2 || got[0] != snellECHTLSALPN || got[1] != snellECHTLSLegacyALPN {
		t.Fatalf("NextProtos = %q", got)
	}
}

func TestSnellECHTLSRejectsConflictingALPNAlias(t *testing.T) {
	echConfig, _, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewSnell(SnellOption{
		Name: "snell", Server: "origin.example.com", Port: 443, Psk: "password", Version: 4,
		ObfsOpts: map[string]any{
			"mode": "ech-tls", "alpn": snellECHTLSALPN,
			"protocol": "other/1", "ech-config": echConfig,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "values conflict") {
		t.Fatalf("NewSnell() error = %v", err)
	}
}

func TestSnellECHTLSAcceptsPreviousProtocolAlias(t *testing.T) {
	got, err := resolveSnellECHTLSALPN("", snellECHTLSPreviousALPN)
	if err != nil || got != snellECHTLSALPN {
		t.Fatalf("resolveSnellECHTLSALPN() = (%q, %v)", got, err)
	}
}

func TestSnellRejectsAnyTLSObfs(t *testing.T) {
	_, err := NewSnell(SnellOption{
		Name:   "snell",
		Server: "127.0.0.1",
		Port:   443,
		Psk:    "password",
		ObfsOpts: map[string]any{
			"mode":     "anytls",
			"password": "outer-password",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "obfs mode error: anytls") {
		t.Fatalf("NewSnell() error = %v, want unsupported anytls obfs", err)
	}
}

func TestSnellRejectsDisabledIdentityForECHTLS(t *testing.T) {
	_, err := NewSnell(SnellOption{
		Name:               "snell",
		Server:             "127.0.0.1",
		Port:               443,
		Psk:                "password",
		Version:            4,
		IdentityConfigured: true,
		ObfsOpts: map[string]any{
			"mode":       "ech-tls",
			"path":       "/snell",
			"ech-config": "invalid",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "identity cannot be disabled") {
		t.Fatalf("NewSnell() error = %v, want disabled identity error", err)
	}
}
