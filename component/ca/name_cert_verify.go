package ca

import (
	"crypto/x509"
	"errors"
	"time"

	"github.com/metacubex/tls"
)

// NewNameCertVerifier returns a verifier for a certificate chain and an explicit DNSName.
func NewNameCertVerifier(dnsName string, roots *x509.CertPool, now func() time.Time) func([]*x509.Certificate) error {
	return func(certificates []*x509.Certificate) error {
		if len(certificates) == 0 {
			return errors.New("tls: no peer certificates")
		}

		intermediates := x509.NewCertPool()
		for _, certificate := range certificates[1:] {
			intermediates.AddCert(certificate)
		}
		verifyOptions := x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			DNSName:       dnsName,
		}
		if now != nil {
			verifyOptions.CurrentTime = now()
		}
		_, err := certificates[0].Verify(verifyOptions)
		return err
	}
}

// SetNameCertVerify replaces the SNI-based check with full chain verification
// against dnsName. Call after installing the final trust pool and clock.
func SetNameCertVerify(config *tls.Config, dnsName string) {
	verifier := NewNameCertVerifier(dnsName, config.RootCAs, config.Time)
	config.VerifyConnection = func(state tls.ConnectionState) error {
		return verifier(state.PeerCertificates)
	}
	config.InsecureSkipVerify = true // VerifyConnection performs chain, time, usage and name checks.
}
