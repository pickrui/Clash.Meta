package ca

import (
	"crypto/x509"
	"testing"
)

func TestEmbeddedOnlyNeverFallsBack(t *testing.T) {
	config, err := GetTLSConfig(Option{EmbeddedOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if config.RootCAs == nil {
		t.Fatal("embedded-only roots fell back to the system store")
	}
	if len(_CaCertificates) == 0 && !config.RootCAs.Equal(x509.NewCertPool()) {
		t.Fatal("an empty bundle trusts something")
	}
}

func TestZeroTrustKeepsItsFallback(t *testing.T) {
	config, err := GetTLSConfig(Option{ZeroTrust: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(_CaCertificates) == 0 && config.RootCAs != nil {
		t.Fatal("zero trust without a bundle no longer uses the system store")
	}
}

func TestHasEmbeddedRootsAgreesWithTheBundle(t *testing.T) {
	want := x509.NewCertPool().AppendCertsFromPEM(_CaCertificates)
	if got := HasEmbeddedRoots(); got != want {
		t.Fatalf("HasEmbeddedRoots = %v, want %v", got, want)
	}
}
