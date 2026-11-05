package vmess

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	"github.com/metacubex/tls"
)

var testRemote = &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}

func TestTLSSessionSecurityBoundaries(t *testing.T) {
	var caches tlsSessionCaches
	base := TLSConfig{Host: "proxy.test", NextProtos: []string{"h2", "http/1.1"}}
	config := &tls.Config{RootCAs: x509.NewCertPool()}
	first := caches.forConfig(&base, config, testRemote)
	if caches.forConfig(&base, config, &net.TCPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 443}) == first {
		t.Fatal("different endpoints share tickets")
	}
	for name, change := range map[string]func(*TLSConfig){
		"server":          func(c *TLSConfig) { c.Host = "other.test" },
		"verification":    func(c *TLSConfig) { c.SkipCertVerify = true },
		"name":            func(c *TLSConfig) { c.NameCertVerify = "verified.test" },
		"pin":             func(c *TLSConfig) { c.FingerPrint = strings.Repeat("01", 32) },
		"alpn":            func(c *TLSConfig) { c.NextProtos = []string{"http/1.1", "h2"} },
		"alpn boundaries": func(c *TLSConfig) { c.NextProtos = []string{"h2http/1.1"} },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			change(&changed)
			if got := caches.forConfig(&changed, config, testRemote); got == nil || got == first {
				t.Fatal("different TLS identities share tickets")
			}
		})
	}
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			copy := base
			if caches.forConfig(&copy, config, testRemote) != first {
				t.Error("concurrent flow lost its shared session cache")
			}
		})
	}
	wg.Wait()
	newTrust := &tls.Config{RootCAs: x509.NewCertPool()}
	if caches.forConfig(&base, newTrust, testRemote) == first {
		t.Fatal("trust pool replacement retained previous tickets")
	}
	if caches.forConfig(&base, config, testRemote) == first {
		t.Fatal("old trust pool retained in the shared cache")
	}
	for name, change := range map[string]func(*TLSConfig){
		"ca file":            func(c *TLSConfig) { c.CAFile = "roots.pem" },
		"client certificate": func(c *TLSConfig) { c.Certificate = "client.pem" },
		"private key":        func(c *TLSConfig) { c.PrivateKey = "client.key" },
		"ech":                func(c *TLSConfig) { c.ECH = &ech.Config{} },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			change(&changed)
			if caches.forConfig(&changed, config, testRemote) != nil {
				t.Fatal("dynamic identity received an implicit session cache")
			}
			explicit := config.Clone()
			explicit.ClientSessionCache = tls.NewLRUClientSessionCache(1)
			if caches.forConfig(&changed, explicit, testRemote) != explicit.ClientSessionCache {
				t.Fatal("replaced the caller's explicit cache")
			}
		})
	}
	quic, err := base.ToStdConfig()
	if err != nil || quic.ClientSessionCache != nil {
		t.Fatalf("config conversion implicitly enabled QUIC resumption: %v", err)
	}
}

func TestTLSSessionCacheBudget(t *testing.T) {
	var caches tlsSessionCaches
	config := &tls.Config{}
	base := &TLSConfig{Host: "oldest.test"}
	oldest := caches.forConfig(base, config, testRemote)
	for i := range tlsSessionCacheBuckets {
		caches.forConfig(&TLSConfig{Host: fmt.Sprintf("proxy-%d.test", i)}, config, testRemote)
	}
	if caches.forConfig(base, config, testRemote) == oldest {
		t.Fatal("cache exceeded its identity budget")
	}
	oldest.Put("first", new(tls.ClientSessionState))
	oldest.Put("second", new(tls.ClientSessionState))
	if _, ok := oldest.Get("first"); ok {
		t.Fatal("one identity retained more than one session")
	}
}

func testSessionServer(t testing.TB, version uint16) (*tls.Config, string) {
	t.Helper()
	certPEM, keyPEM, pin, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: version, MaxVersion: version}, pin
}

func testSessionListener(t testing.TB) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func testSessionHandshake(t testing.TB, listener net.Listener, server *tls.Config, cfg *TLSConfig) (bool, error) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		serverSide, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer serverSide.Close()
		_ = serverSide.SetDeadline(time.Now().Add(5 * time.Second))
		conn := tls.Server(serverSide, server)
		_, err = conn.Write([]byte("ok"))
		done <- err
	}()
	clientSide, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer clientSide.Close()
	_ = clientSide.SetDeadline(time.Now().Add(5 * time.Second))
	conn, err := StreamTLSConn(context.Background(), clientSide, cfg)
	if err != nil {
		_ = clientSide.Close()
		<-done
		return false, err
	}
	var payload [2]byte
	if _, err := io.ReadFull(conn, payload[:]); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if string(payload[:]) != "ok" {
		t.Fatal("resumed connection corrupted payload")
	}
	return conn.(*tls.Conn).ConnectionState().DidResume, nil
}

func TestStreamTLSResumesAcrossFlows(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			server, pin := testSessionServer(t, version)
			listener := testSessionListener(t)
			for attempt := range 3 {
				resumed, err := testSessionHandshake(t, listener, server, &TLSConfig{Host: t.Name(), FingerPrint: pin})
				if err != nil || resumed != (attempt > 0) {
					t.Fatalf("flow %d: resumed=%v, err=%v", attempt, resumed, err)
				}
			}
			resumed, err := testSessionHandshake(t, testSessionListener(t), server, &TLSConfig{Host: t.Name(), FingerPrint: pin})
			if err != nil || resumed {
				t.Fatalf("another endpoint with the same name: resumed=%v, err=%v", resumed, err)
			}
			if _, err := testSessionHandshake(t, listener, server, &TLSConfig{Host: t.Name(), FingerPrint: strings.Repeat("00", 32)}); err == nil {
				t.Fatal("a cached session bypassed a changed certificate pin")
			}
			ca.ResetCertificate()
			resumed, err = testSessionHandshake(t, listener, server, &TLSConfig{Host: t.Name(), FingerPrint: pin})
			if err != nil || resumed {
				t.Fatalf("trust reset: resumed=%v, err=%v", resumed, err)
			}
			withoutTickets := server.Clone()
			withoutTickets.SessionTicketsDisabled = true
			for range 2 {
				resumed, err := testSessionHandshake(t, listener, withoutTickets, &TLSConfig{Host: t.Name(), FingerPrint: pin})
				if err != nil || resumed {
					t.Fatalf("server without tickets: resumed=%v, err=%v", resumed, err)
				}
			}
		})
	}
}
