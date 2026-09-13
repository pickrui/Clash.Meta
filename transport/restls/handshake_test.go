package restls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	tls "github.com/metacubex/restls-client-go"
)

// Both the camouflage TLS target and the Restls peer are local test servers.
func restlsTestPeer(t *testing.T, version uint16, observeSNI ...func(string)) (string, *x509.CertPool, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(19), DNSNames: []string{"restls.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	targetConfig := &stdtls.Config{Certificates: []stdtls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: version, MaxVersion: version}
	if len(observeSNI) > 0 {
		targetConfig.GetConfigForClient = func(hello *stdtls.ClientHelloInfo) (*stdtls.Config, error) {
			observeSNI[0](hello.ServerName)
			return nil, nil
		}
	}
	target := restlsTestListener(t, func(conn net.Conn) {
		secured := stdtls.Server(conn, targetConfig)
		defer secured.Close()
		_, _ = io.Copy(io.Discard, secured)
	})
	serverConfig := &tls.RestlsServerConfig{ServerHostname: target, Password: "local-restls-password"}
	peer := restlsTestListener(t, func(conn net.Conn) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		plain, err := tls.RestlsServer(ctx, conn, serverConfig)
		if err != nil {
			return
		} // Negative certificate tests deliberately abort the handshake.
		defer plain.Close()
		// Echo complete records so writes larger than a TLS record cannot deadlock.
		buf := make([]byte, 2048)
		for {
			n, err := plain.Read(buf)
			if n > 0 {
				if _, err := plain.Write(buf[:n]); err != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	})
	return peer, roots, ca.CalculateFingerprint(der)
}

func restlsTestListener(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var active sync.Map
	var workers sync.WaitGroup
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			active.Store(conn, struct{}{})
			workers.Go(func() {
				defer active.Delete(conn)
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				handle(conn)
			})
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		<-accepted
		active.Range(func(key, _ any) bool { key.(net.Conn).Close(); return true })
		workers.Wait()
	})
	return listener.Addr().String()
}

func restlsTestExchange(address string, config *Config) (tls.ConnectionState, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	conn, err := NewRestls(ctx, raw, config)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer conn.Close()
	state := conn.(*Restls).ConnectionState()
	// Read concurrently while writing a payload spanning several Restls/TLS records.
	payload := bytes.Repeat([]byte("restls-round-trip/"), 2048)
	written := make(chan error, 1)
	go func() { _, err := conn.Write(payload); written <- err }()
	response := make([]byte, len(payload))
	_, readErr := io.ReadFull(conn, response)
	if readErr != nil {
		raw.Close()
	}
	if writeErr := <-written; writeErr != nil {
		return state, writeErr
	}
	if readErr != nil {
		return state, readErr
	}
	if !bytes.Equal(payload, response) {
		return state, fmt.Errorf("Restls payload changed")
	}
	return state, nil
}

func TestClientLocalHandshakeAndSessionReuse(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(fmt.Sprintf("tls%x", version), func(t *testing.T) {
			address, roots, _ := restlsTestPeer(t, version)
			hint := "tls13"
			if version == tls.VersionTLS12 {
				hint = "tls12"
			}
			for _, fingerprint := range []string{"chrome", "firefox", "safari", "ios"} {
				t.Run(fingerprint, func(t *testing.T) {
					config, err := NewRestlsConfig("restls.test", "local-restls-password", hint, "", fingerprint)
					if err != nil {
						t.Fatal(err)
					}
					config.RootCAs = roots
					config.ForceTLS12 = version == tls.VersionTLS12
					for i := range 2 {
						state, err := restlsTestExchange(address, config)
						if err != nil {
							t.Fatal(err)
						}
						if state.Version != version {
							t.Fatalf("version=%x want=%x", state.Version, version)
						}
						if want := version == tls.VersionTLS12 && i == 1 && (fingerprint == "chrome" || fingerprint == "firefox"); state.DidResume != want {
							t.Fatalf("connection %d resumed=%v want=%v", i, state.DidResume, want)
						}
					}
					if config.MinVersion != 0 || config.MaxVersion != 0 {
						t.Fatal("successful handshake changed shared configuration")
					}
				})
			}
		})
	}
}

func TestClientLocalCertificateVerification(t *testing.T) {
	address, roots, fingerprint := restlsTestPeer(t, tls.VersionTLS13)
	for _, test := range []struct {
		name          string
		trusted, skip bool
		host, pin     string
		wantError     bool
	}{
		{name: "trusted", trusted: true},
		{name: "untrusted", wantError: true},
		{name: "wrong_name", trusted: true, host: "wrong.test", wantError: true},
		{name: "pinned_leaf", pin: fingerprint},
		{name: "wrong_pin", trusted: true, pin: fmt.Sprintf("%064x", 0), wantError: true},
		{name: "explicit_skip", skip: true},
		{name: "pin_still_enforced_with_skip", skip: true, pin: fmt.Sprintf("%064x", 0), wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			host := test.host
			if host == "" {
				host = "restls.test"
			}
			config, err := NewRestlsConfig(host, "local-restls-password", "tls13", "", "chrome")
			if err != nil {
				t.Fatal(err)
			}
			config.RootCAs = x509.NewCertPool()
			if test.trusted {
				config.RootCAs = roots
			}
			config.InsecureSkipVerify = test.skip
			if test.pin != "" {
				if err := SetFingerprint(config, test.pin, ""); err != nil {
					t.Fatal(err)
				}
			}
			_, err = restlsTestExchange(address, config)
			if (err != nil) != test.wantError {
				t.Fatalf("handshake error=%v wantError=%v", err, test.wantError)
			}
		})
	}
}

func TestClientConcurrentSuccessfulHandshakes(t *testing.T) {
	address, roots, _ := restlsTestPeer(t, tls.VersionTLS13)
	config, err := NewRestlsConfig("restls.test", "local-restls-password", "tls13", "", "chrome")
	if err != nil {
		t.Fatal(err)
	}
	config.RootCAs = roots
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			if _, err := restlsTestExchange(address, config); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if config.MinVersion != 0 || config.MaxVersion != 0 {
		t.Fatal("concurrent handshakes changed shared configuration")
	}
}
