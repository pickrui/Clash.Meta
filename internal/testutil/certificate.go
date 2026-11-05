// Package testutil provides local certificate fixtures for transport tests.
package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/metacubex/tls"
	"github.com/stretchr/testify/require"
)

type Certificate struct {
	TLS     tls.Certificate
	Root    *x509.Certificate
	Leaf    *x509.Certificate
	RootPEM string
}

// NewCertificate creates a private CA and a server certificate valid only for names.
func NewCertificate(t testing.TB, names ...string) Certificate {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: names, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &leafKey.PublicKey, rootKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)
	return Certificate{TLS: tls.Certificate{Certificate: [][]byte{leafDER, rootDER}, PrivateKey: leafKey}, Root: root, Leaf: leaf, RootPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}))}
}

// PEM returns the certificate chain and leaf key for inbound configuration.
func (c Certificate) PEM(t testing.TB) (string, string) {
	t.Helper()
	key, err := x509.MarshalPKCS8PrivateKey(c.TLS.PrivateKey)
	require.NoError(t, err)
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Leaf.Raw})
	return string(chain) + c.RootPEM, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
}
