package restls

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/ntp"
)

func TestConfigUsesGlobalTrustAndAdjustedTime(t *testing.T) {
	oldSystem, oldEmbed, oldOffset := ca.DisableSystemCa, ca.DisableEmbedCa, ntp.GetOffset()
	ca.DisableSystemCa, ca.DisableEmbedCa = true, true
	ca.ResetCertificate()
	t.Cleanup(func() {
		ca.DisableSystemCa, ca.DisableEmbedCa = oldSystem, oldEmbed
		ca.ResetCertificate()
		ntp.SetOffset(oldOffset)
	})
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{"restls.test"},
		NotBefore: now.Add(23 * time.Hour), NotAfter: now.Add(25 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.AddCertificate(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))); err != nil {
		t.Fatal(err)
	}
	config, err := NewRestlsConfig("restls.test", "test-password", "tls13", "", "chrome")
	if err != nil {
		t.Fatal(err)
	}
	if config.InsecureSkipVerify {
		t.Fatal("certificate verification disabled")
	}
	if config.RootCAs == nil {
		t.Error("global certificate pool missing")
	}
	if config.Time == nil {
		t.Fatal("adjusted clock missing")
	}
	// Change the clock after construction: the config must observe subsequent NTP updates.
	ntp.SetOffset(24 * time.Hour)
	opts := x509.VerifyOptions{Roots: config.RootCAs, DNSName: config.ServerName, CurrentTime: config.Time()}
	if _, err := cert.Verify(opts); err != nil {
		t.Fatalf("trusted certificate at adjusted time: %v", err)
	}
	opts.DNSName = "other.test"
	if _, err := cert.Verify(opts); err == nil {
		t.Fatal("wrong hostname accepted")
	}
	opts.DNSName = config.ServerName
	opts.Roots = x509.NewCertPool()
	if _, err := cert.Verify(opts); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	ntp.SetOffset(0)
	opts.Roots, opts.CurrentTime = config.RootCAs, config.Time()
	if _, err := cert.Verify(opts); err == nil {
		t.Fatal("not-yet-valid certificate accepted at system time")
	}
}

func TestConfigPreservesRestlsOptionsAndErrors(t *testing.T) {
	for _, version := range []string{"tls12", "tls13"} {
		config, err := NewRestlsConfig("restls.test", "test-password", version, "", "firefox")
		if err != nil {
			t.Fatal(err)
		}
		if config.ServerName != "restls.test" || len(config.RestlsSecret) != 32 || config.ClientID.Load() == nil || config.ClientSessionCache == nil {
			t.Fatalf("incomplete Restls configuration for %s", version)
		}
		if config.SessionTicketsDisabled != (version == "tls13") {
			t.Fatalf("session ticket policy changed for %s", version)
		}
	}
	if config, err := NewRestlsConfig("restls.test", "password", "invalid", "", "chrome"); err == nil || config != nil {
		t.Fatalf("invalid version: config=%v err=%v", config, err)
	}
}
