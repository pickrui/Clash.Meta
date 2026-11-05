package ca

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/tls"
)

func TestTLSKeyPairReloadPreservesReturnedCertificate(t *testing.T) {
	previousHome := C.Path.HomeDir()
	C.SetHomeDir(t.TempDir())
	t.Cleanup(func() { C.SetHomeDir(previousHome) })
	certPath := filepath.Join(C.Path.HomeDir(), "cert.pem")
	keyPath := filepath.Join(C.Path.HomeDir(), "key.pem")
	writePair := func(cert, key string) {
		t.Helper()
		if err := os.WriteFile(certPath, []byte(cert), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, []byte(key), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cert, key, _, err := NewRandomTLSKeyPair(KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	writePair(cert, key)
	loader, err := NewTLSKeyPairLoader(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { runtime.KeepAlive(loader) }()
	original, err := loader()
	if err != nil {
		t.Fatal(err)
	}
	originalDER := bytes.Clone(original.Certificate[0])
	cert, key, _, err = NewRandomTLSKeyPair(KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	writePair(cert, key)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		current, err := loader()
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(current.Certificate[0], replacement.Certificate[0]) {
			break
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("certificate file update was not loaded")
		}
	}
	if !bytes.Equal(original.Certificate[0], originalDER) {
		t.Fatal("reload modified a certificate still held by an active handshake")
	}
}
