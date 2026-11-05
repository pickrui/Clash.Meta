package outbound

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/tls"
	"github.com/stretchr/testify/require"
)

func TestProxyTLSSessionReuse(t *testing.T) {
	certPEM, keyPEM, pin, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	require.NoError(t, err)
	configs := func(cert, key string) []*tls.Config {
		httpProxy, err := NewHttp(HttpOption{Name: "fixture", Server: "proxy.test", Port: 443, TLS: true, Fingerprint: pin, Certificate: cert, PrivateKey: key})
		require.NoError(t, err)
		socksProxy, err := NewSocks5(Socks5Option{Name: "fixture", Server: "proxy.test", Port: 443, TLS: true, Fingerprint: pin, Certificate: cert, PrivateKey: key})
		require.NoError(t, err)
		return []*tls.Config{httpProxy.tlsConfig, socksProxy.tlsConfig}
	}
	first, replacement := configs("", ""), configs("", "")
	for i, config := range first {
		require.NotNil(t, config.ClientSessionCache)
		require.NotSame(t, config.ClientSessionCache, replacement[i].ClientSessionCache, "replacement outbound inherited the old sessions")
	}
	for _, config := range configs(certPEM, keyPEM) {
		require.Nil(t, config.ClientSessionCache, "session reuse may bypass a client certificate reload")
	}

	certificate, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	require.NoError(t, err)
	serverConfig := &tls.Config{Certificates: []tls.Certificate{certificate}}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	go func() {
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			conn := tls.Server(raw, serverConfig)
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			_, _ = conn.Write([]byte{1})
			_ = conn.Close()
		}
	}()
	for attempt := range 2 {
		raw, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
		require.NoError(t, err)
		conn := tls.Client(raw, first[0])
		require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
		_, err = io.ReadFull(conn, make([]byte, 1))
		require.NoError(t, err)
		require.Equal(t, attempt > 0, conn.ConnectionState().DidResume, "connection %d", attempt)
		_ = conn.Close()
	}
}
