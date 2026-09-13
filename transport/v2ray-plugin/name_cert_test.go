package obfs

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/internal/testutil"
	"github.com/metacubex/tls"
	"github.com/stretchr/testify/require"
)

func TestWebsocketPrivateCANameVerification(t *testing.T) {
	cert := testutil.NewCertificate(t, "certificate.test")
	other := testutil.NewCertificate(t, "certificate.test")
	for _, scenario := range []string{"valid", "wrong name", "untrusted"} {
		t.Run(scenario, func(t *testing.T) {
			option := &Option{Host: "request.test", ServerName: "front.test", Headers: map[string]string{"Host": "request.test"}, TLS: true, CAFile: cert.RootPEM, NameCertVerify: "certificate.test"}
			wantErr := scenario != "valid"
			if scenario == "wrong name" {
				option.NameCertVerify = "wrong.test"
			}
			if scenario == "untrusted" {
				option.CAFile = other.RootPEM
			}
			config, err := newWebsocketConfig(option)
			require.NoError(t, err)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer listener.Close()
			seen := make(chan string, 1)
			done := make(chan error, 1)
			go func() {
				raw, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer raw.Close()
				_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
				conn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert.TLS}})
				err = conn.Handshake()
				if err == nil {
					seen <- conn.ConnectionState().ServerName
					_, err = conn.Write([]byte{1})
				}
				done <- err
			}()
			raw, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
			require.NoError(t, err)
			defer raw.Close()
			_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
			conn := tls.Client(raw, config.TLSConfig)
			err = conn.HandshakeContext(context.Background())
			if wantErr {
				require.Error(t, err)
				_ = raw.Close()
				<-done
				return
			}
			require.NoError(t, err)
			_, err = io.ReadFull(conn, make([]byte, 1))
			require.NoError(t, err)
			require.NoError(t, <-done)
			require.Equal(t, "front.test", <-seen)
			require.Equal(t, "request.test", config.Headers.Get("Host"))
		})
	}
}
