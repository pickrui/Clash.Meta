// Package testutil provides loopback-only QUIC fixtures for TUIC tests.
package testutil

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

func TLSConfigs(t testing.TB) (server, client *tls.Config) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	server = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}, NextProtos: []string{"tuic-test"}}
	client = &tls.Config{RootCAs: roots, ServerName: "localhost", NextProtos: []string{"tuic-test"}}
	return
}

func StreamLimitedConn(t testing.TB) *quic.Conn {
	t.Helper()
	serverTLS, clientTLS := TLSConfigs(t)
	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, &quic.Config{MaxIncomingStreams: -1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := quic.DialAddr(ctx, listener.Addr().String(), clientTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.CloseWithError(0, "test complete") })
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.CloseWithError(0, "test complete") })
	return client
}
