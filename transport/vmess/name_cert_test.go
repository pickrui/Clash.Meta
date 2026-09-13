package vmess

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/internal/testutil"
	"github.com/metacubex/tls"
	"github.com/stretchr/testify/require"
)

func TestStreamTLSNameCertVerify(t *testing.T) {
	cert := testutil.NewCertificate(t, "certificate.test")
	other := testutil.NewCertificate(t, "certificate.test")
	dir := t.TempDir()
	originalHome := C.Path.HomeDir()
	C.SetHomeDir(dir)
	t.Cleanup(func() { C.SetHomeDir(originalHome) })
	rootFile := filepath.Join(dir, "private-ca.pem")
	require.NoError(t, os.WriteFile(rootFile, []byte(cert.RootPEM), 0600))
	for _, fingerprint := range []string{"", "chrome"} {
		for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
			for _, scenario := range []string{"private CA inline", "private CA file", "wrong name", "default SNI check", "untrusted CA", "leaf pin", "CA pin", "wrong CA pin name"} {
				t.Run(fmt.Sprintf("%s/%x/%s", fingerprint, version, scenario), func(t *testing.T) {
					cfg := &TLSConfig{Host: "front.test", NameCertVerify: "certificate.test", CAFile: cert.RootPEM, ClientFingerprint: fingerprint}
					wantErr := false
					switch scenario {
					case "private CA file":
						cfg.CAFile = rootFile
					case "wrong name":
						cfg.NameCertVerify = "wrong.test"
						wantErr = true
					case "default SNI check":
						cfg.NameCertVerify = ""
						wantErr = true
					case "untrusted CA":
						cfg.CAFile = other.RootPEM
						wantErr = true
					case "leaf pin":
						cfg.FingerPrint = ca.CalculateFingerprint(cert.Leaf.Raw)
						cfg.NameCertVerify = "wrong.test"
						cfg.CAFile = other.RootPEM
					case "CA pin":
						cfg.FingerPrint = ca.CalculateFingerprint(cert.Root.Raw)
						cfg.CAFile = other.RootPEM
					case "wrong CA pin name":
						cfg.FingerPrint = ca.CalculateFingerprint(cert.Root.Raw)
						cfg.NameCertVerify = "wrong.test"
						wantErr = true
					}
					checkNameTLSHandshake(t, &tls.Config{Certificates: []tls.Certificate{cert.TLS}, MinVersion: version, MaxVersion: version}, cfg, wantErr, false)
				})
			}
		}
	}
}

func TestStreamTLSNameCertVerifyECH(t *testing.T) {
	cert := testutil.NewCertificate(t, "certificate.test")
	encoded, keyPEM, err := ech.GenECHConfig("public.test")
	require.NoError(t, err)
	echList, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)
	for _, fingerprint := range []string{"", "chrome"} {
		for _, wrong := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/wrong=%t", fingerprint, wrong), func(t *testing.T) {
				server := &tls.Config{Certificates: []tls.Certificate{cert.TLS}, MinVersion: tls.VersionTLS13, NextProtos: []string{"snell-ech/1"}}
				require.NoError(t, ech.LoadECHKey(keyPEM, server))
				name := "certificate.test"
				if wrong {
					name = "wrong.test"
				}
				cfg := &TLSConfig{Host: "front.test", NameCertVerify: name, CAFile: cert.RootPEM, ClientFingerprint: fingerprint, NextProtos: []string{"snell-ech/1"}, DisableRenegotiation: true, ECH: &ech.Config{GetEncryptedClientHelloConfigList: func(context.Context, string) ([]byte, error) { return echList, nil }}}
				checkNameTLSHandshake(t, server, cfg, wrong, true)
			})
		}
	}
}

func checkNameTLSHandshake(t *testing.T, serverConfig *tls.Config, cfg *TLSConfig, wantErr, expectECH bool) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	type result struct {
		state    tls.ConnectionState
		exporter []byte
		err      error
	}
	done := make(chan result, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			done <- result{err: err}
			return
		}
		defer raw.Close()
		_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
		server := tls.Server(raw, serverConfig)
		err = server.Handshake()
		state := server.ConnectionState()
		var exporter []byte
		if err == nil {
			if expectECH {
				exporter, err = state.ExportKeyingMaterial("EXPORTER-Dler-Snell-Identity-v2", []byte{}, 32)
			}
			if err == nil {
				_, err = server.Write([]byte{1})
			}
		}
		done <- result{state, exporter, err}
	}()
	raw, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
	require.NoError(t, err)
	defer raw.Close()
	require.NoError(t, raw.SetDeadline(time.Now().Add(5*time.Second)))
	conn, err := StreamTLSConn(context.Background(), raw, cfg)
	if wantErr {
		require.Error(t, err)
		_ = raw.Close()
		<-done
		return
	}
	require.NoError(t, err)
	_, err = io.ReadFull(conn, make([]byte, 1))
	require.NoError(t, err)
	server := <-done
	require.NoError(t, server.err)
	require.Equal(t, "front.test", server.state.ServerName)
	state := tlsC.GetTLSConnectionState(conn)
	require.Equal(t, expectECH, state.ECHAccepted)
	require.Equal(t, expectECH, server.state.ECHAccepted)
	if expectECH {
		exporter, err := state.ExportKeyingMaterial("EXPORTER-Dler-Snell-Identity-v2", []byte{}, 32)
		require.NoError(t, err)
		require.Equal(t, server.exporter, exporter)
		require.Equal(t, "snell-ech/1", state.NegotiatedProtocol)
	}
}
