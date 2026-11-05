package outbound

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/internal/testutil"
	"github.com/metacubex/mihomo/transport/tuic"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
	"github.com/stretchr/testify/require"
)

func TestTuicConfigOptions(t *testing.T) {
	for _, alpn := range [][]string{nil, {}, {"custom"}} {
		option := tuicMemoryOption("")
		option.ALPN = alpn
		node, err := NewTuic(option)
		require.NoError(t, err)
		t.Cleanup(func() { _ = node.Close() })
		require.Nil(t, node.quicConfig)
		tlsConfig, config := node.dialConfigs()
		wantALPN := alpn
		if wantALPN == nil {
			wantALPN = []string{"h3"}
		}
		require.Equal(t, wantALPN, tlsConfig.NextProtos)
		require.Equal(t, uint16(tls.VersionTLS13), tlsConfig.MinVersion)
		require.NotNil(t, tlsConfig.Time)
		require.Equal(t, 10*time.Second, config.KeepAlivePeriod)
		require.Equal(t, int64(110), config.MaxIncomingStreams)
		require.Equal(t, int64(110), config.MaxIncomingUniStreams)
		require.Equal(t, uint64(tuic.DefaultStreamReceiveWindow), config.MaxStreamReceiveWindow)
		require.Equal(t, uint64(tuic.DefaultConnectionReceiveWindow), config.MaxConnectionReceiveWindow)
		require.Equal(t, int64(1252+tuic.PacketOverHeadV5), config.MaxDatagramFrameSize)
	}
	option := tuicMemoryOption("fixture-token")
	option.ReceiveWindowConn, option.ReceiveWindow = 2048, 4096
	option.MaxOpenStreams, option.HeartbeatInterval = 7, 2345
	option.DisableMTUDiscovery, option.MaxDatagramFrameSize = true, 1500
	node, err := NewTuic(option)
	require.NoError(t, err)
	defer node.Close()
	_, config := node.dialConfigs()
	require.Equal(t, uint64(2048), config.InitialStreamReceiveWindow)
	require.Equal(t, uint64(2048), config.MaxStreamReceiveWindow)
	require.Equal(t, uint64(4096), config.InitialConnectionReceiveWindow)
	require.Equal(t, uint64(4096), config.MaxConnectionReceiveWindow)
	require.Equal(t, int64(8), config.MaxIncomingStreams)
	require.Equal(t, 2345*time.Millisecond, config.KeepAlivePeriod)
	require.Equal(t, int64(1400), config.MaxDatagramFrameSize)
	require.True(t, config.DisablePathMTUDiscovery)
}

type tuicLoopbackDialer struct{ tuicOfflineDialer }

func (tuicLoopbackDialer) ListenPacket(ctx context.Context, _, _ string, _ netip.AddrPort) (net.PacketConn, error) {
	return (&net.ListenConfig{}).ListenPacket(ctx, "udp4", "127.0.0.1:0")
}

func TestTuicTLSHandshakePreservesTrust(t *testing.T) {
	cert := testutil.NewCertificate(t, "proxy.test", "certificate.test")
	for _, kind := range []string{"ordinary", "name", "pin", "disabled-sni", "disabled-sni-name", "skip-verify", "wrong-name", "wrong-pin"} {
		t.Run(kind, func(t *testing.T) {
			require.NoError(t, ca.AddCertificate(cert.RootPEM))
			t.Cleanup(ca.ResetCertificate)
			server, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
				Certificates: []tls.Certificate{cert.TLS}, NextProtos: []string{"h3"},
			}, &quic.Config{EnableDatagrams: true})
			require.NoError(t, err)
			defer server.Close()
			option := tuicMemoryOption("")
			option.Port = server.Addr().(*net.UDPAddr).Port
			switch kind {
			case "name":
				option.SNI, option.NameCertVerify = "front.test", "certificate.test"
			case "pin":
				option.Fingerprint = ca.CalculateFingerprint(cert.Leaf.Raw)
			case "disabled-sni":
				option.DisableSni = true
			case "disabled-sni-name":
				option.DisableSni, option.NameCertVerify = true, "certificate.test"
			case "skip-verify":
				option.SkipCertVerify, option.SNI = true, "wrong.test"
			case "wrong-name":
				option.SNI = "wrong.test"
			case "wrong-pin":
				option.Fingerprint = ca.CalculateFingerprint([]byte("other certificate"))
			}
			node, err := NewTuic(option)
			require.NoError(t, err)
			defer node.Close()
			node.dialer = tuicLoopbackDialer{}
			ca.ResetCertificate()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, err := node.dial(ctx)
			if kind == "wrong-name" || kind == "wrong-pin" {
				if conn != nil {
					_ = conn.CloseWithError(0, "unexpected success")
				}
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			defer conn.CloseWithError(0, "done")
			accepted, err := server.Accept(ctx)
			require.NoError(t, err)
			defer accepted.CloseWithError(0, "done")
			wantSNI := option.SNI
			if option.DisableSni {
				wantSNI = ""
			}
			require.Equal(t, wantSNI, accepted.ConnectionState().TLS.ServerName)
			require.Equal(t, "h3", conn.ConnectionState().TLS.NegotiatedProtocol)
		})
	}
}

func TestTuicClientCertificateKeepsParsedLoader(t *testing.T) {
	previousHome := C.Path.HomeDir()
	C.SetHomeDir(t.TempDir())
	t.Cleanup(func() { C.SetHomeDir(previousHome) })
	cert := testutil.NewCertificate(t, "client.test")
	certPEM, keyPEM := cert.PEM(t)
	option := tuicMemoryOption("")
	option.Certificate = filepath.Join(C.Path.HomeDir(), "cert.pem")
	option.PrivateKey = filepath.Join(C.Path.HomeDir(), "key.pem")
	require.NoError(t, os.WriteFile(option.Certificate, []byte(certPEM), 0600))
	require.NoError(t, os.WriteFile(option.PrivateKey, []byte(keyPEM), 0600))
	node, err := NewTuic(option)
	require.NoError(t, err)
	defer node.Close()
	parsed := node.tlsConfig
	require.NotNil(t, parsed)
	require.NoError(t, os.Remove(option.Certificate))
	require.NoError(t, os.Remove(option.PrivateKey))
	config, _ := node.dialConfigs()
	require.Same(t, parsed, config)
	loaded, err := config.GetClientCertificate(&tls.CertificateRequestInfo{})
	require.NoError(t, err)
	require.Equal(t, cert.Leaf.Raw, loaded.Certificate[0])
	_, err = NewTuic(option)
	require.Error(t, err)
	option.Certificate, option.PrivateKey, option.Fingerprint = "", "", "bad fingerprint"
	_, err = NewTuic(option)
	require.Error(t, err)
}
