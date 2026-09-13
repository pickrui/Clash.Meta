package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	stdtls "crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/metacubex/tls"
	"github.com/stretchr/testify/require"
)

// These tests use only generated certificates and loopback sockets. The server
// certificate is for origin.test while the client sends front.test as SNI.
func nameVerifyCertificates(t *testing.T, expired, clientOnly bool) (stdtls.Certificate, *x509.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &key.PublicKey, key)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"origin.test"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	if expired {
		leafTemplate.NotAfter = now.Add(-time.Minute)
	}
	if clientOnly {
		leafTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &key.PublicKey, key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)
	return stdtls.Certificate{Certificate: [][]byte{leafDER, rootDER}, PrivateKey: key}, root, leaf
}

func nameVerifyRoots(t *testing.T, roots *x509.CertPool) {
	t.Helper()
	mutex.Lock()
	original := globalCertPool
	globalCertPool = roots
	mutex.Unlock()
	t.Cleanup(func() { mutex.Lock(); globalCertPool = original; mutex.Unlock() })
}

func nameVerifyHandshake(t *testing.T, serverConfig *stdtls.Config, clientConfig *tls.Config, wantErr bool) tls.ConnectionState {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	serverSNI := make(chan string, 1)
	serverDone := make(chan error, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer raw.Close()
		_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
		config := serverConfig.Clone()
		config.GetConfigForClient = func(hello *stdtls.ClientHelloInfo) (*stdtls.Config, error) {
			serverSNI <- hello.ServerName
			return nil, nil
		}
		conn := stdtls.Server(raw, config)
		err = conn.Handshake()
		if err == nil {
			_, err = conn.Write([]byte{1})
		}
		serverDone <- err
	}()
	raw, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
	require.NoError(t, err)
	defer raw.Close()
	require.NoError(t, raw.SetDeadline(time.Now().Add(5*time.Second)))
	client := tls.Client(raw, clientConfig)
	err = client.Handshake()
	if wantErr {
		require.Error(t, err)
	} else {
		require.NoError(t, err)
		_, err = io.ReadFull(client, make([]byte, 1)) // Process TLS 1.3 session tickets.
		require.NoError(t, err)
	}
	require.Equal(t, "front.test", <-serverSNI)
	serverErr := <-serverDone
	if !wantErr {
		require.NoError(t, serverErr)
	}
	return client.ConnectionState()
}

func TestNameCertTLSHandshake(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(fmt.Sprintf("%x", version), func(t *testing.T) {
			for _, tc := range []struct {
				name, verify, pin                             string
				skip, untrusted, expired, clientOnly, wantErr bool
			}{
				{name: "explicit name", verify: "origin.test"},
				{name: "default still checks SNI", wantErr: true},
				{name: "default skip unchanged", skip: true},
				{name: "wrong name", verify: "wrong.test", wantErr: true},
				{name: "skip cannot bypass explicit name", verify: "wrong.test", skip: true, wantErr: true},
				{name: "untrusted root", verify: "origin.test", untrusted: true, wantErr: true},
				{name: "expired", verify: "origin.test", expired: true, wantErr: true},
				{name: "wrong certificate usage", verify: "origin.test", clientOnly: true, wantErr: true},
				{name: "CA pin explicit name", verify: "origin.test", pin: "root", untrusted: true},
				{name: "CA pin wrong name", verify: "wrong.test", pin: "root", wantErr: true},
				{name: "CA pin expired", verify: "origin.test", pin: "root", expired: true, wantErr: true},
				{name: "leaf pin precedence unchanged", verify: "wrong.test", pin: "leaf", untrusted: true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					cert, root, leaf := nameVerifyCertificates(t, tc.expired, tc.clientOnly)
					roots := x509.NewCertPool()
					if !tc.untrusted {
						roots.AddCert(root)
					}
					nameVerifyRoots(t, roots)
					pin := ""
					if tc.pin == "root" {
						pin = fmt.Sprintf("%x", sha256.Sum256(root.Raw))
					}
					if tc.pin == "leaf" {
						pin = fmt.Sprintf("%x", sha256.Sum256(leaf.Raw))
					}
					config, err := GetTLSConfig(Option{TLSConfig: &tls.Config{ServerName: "front.test", InsecureSkipVerify: tc.skip, MinVersion: version, MaxVersion: version}, NameCertVerify: tc.verify, Fingerprint: pin})
					require.NoError(t, err)
					if tc.verify == "" && pin == "" {
						require.Nil(t, config.VerifyConnection)
						require.Equal(t, tc.skip, config.InsecureSkipVerify)
					}
					nameVerifyHandshake(t, &stdtls.Config{Certificates: []stdtls.Certificate{cert}, MinVersion: version, MaxVersion: version}, config, tc.wantErr)
				})
			}
		})
	}
}

func TestNameCertTLSResumptionRechecksName(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(fmt.Sprintf("%x", version), func(t *testing.T) {
			cert, root, _ := nameVerifyCertificates(t, false, false)
			roots := x509.NewCertPool()
			roots.AddCert(root)
			nameVerifyRoots(t, roots)
			server := &stdtls.Config{Certificates: []stdtls.Certificate{cert}, MinVersion: version, MaxVersion: version}
			// A fixed test ticket key lets separate loopback listeners resume sessions.
			server.SetSessionTicketKeys([][32]byte{{1}})
			cache := tls.NewLRUClientSessionCache(2)
			for attempt := range 3 {
				name := "origin.test"
				if attempt == 2 {
					name = "wrong.test"
				}
				config, err := GetTLSConfig(Option{TLSConfig: &tls.Config{ServerName: "front.test", MinVersion: version, MaxVersion: version, ClientSessionCache: cache}, NameCertVerify: name})
				require.NoError(t, err)
				verify := config.VerifyConnection
				called, resumed := false, false
				config.VerifyConnection = func(state tls.ConnectionState) error { called = true; resumed = state.DidResume; return verify(state) }
				nameVerifyHandshake(t, server, config, attempt == 2)
				require.True(t, called)
				require.Equal(t, attempt > 0, resumed)
			}
		})
	}
}
