package inbound_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/structure"
	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/internal/testutil"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/tls"
	"github.com/stretchr/testify/require"
)

func nameCertificateFront(t *testing.T, target string, config *tls.Config) (int, *atomic.Int32) {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", config)
	require.NoError(t, err)
	var count atomic.Int32
	var workers sync.WaitGroup
	var active sync.Map
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			active.Store(conn, struct{}{})
			workers.Go(func() {
				defer active.Delete(conn)
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				if err := conn.(*tls.Conn).Handshake(); err != nil {
					return
				}
				peer, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer peer.Close()
				count.Add(1)
				N.Relay(conn, peer)
			})
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
		active.Range(func(k, _ any) bool { _ = k.(net.Conn).Close(); return true })
		workers.Wait()
	})
	return listener.Addr().(*net.TCPAddr).Port, &count
}

func TestInboundVless_NameCertDownload(t *testing.T) {
	upload := testutil.NewCertificate(t, "upload-certificate.test")
	download := testutil.NewCertificate(t, "download-certificate.test", "download-front.test", "upload-certificate.test")
	require.NoError(t, ca.AddCertificate(upload.RootPEM))
	require.NoError(t, ca.AddCertificate(download.RootPEM))
	t.Cleanup(ca.ResetCertificate)
	for _, transport := range []string{"tls", "restls"} {
		for _, alpn := range []string{"http/1.1", "h2"} {
			for _, scenario := range []string{"inherit", "override", "clear", "wrong name"} {
				t.Run(transport+"/"+alpn+"/"+scenario, func(t *testing.T) {
					tunnel := &TestTunnel{HandleTCPConnFn: func(conn net.Conn, metadata *C.Metadata) {
						defer conn.Close()
						_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
						if metadata.Type == C.INNER {
							config := &tls.Config{NextProtos: []string{alpn}, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
								if hello.ServerName == "download-front.test" {
									return &download.TLS, nil
								}
								return &upload.TLS, nil
							}}
							_, _ = io.Copy(io.Discard, tls.Server(conn, config))
							return
						}
						_, _ = io.Copy(conn, conn)
					}}
					in, err := inbound.NewVless(&inbound.VlessOption{BaseOption: inbound.BaseOption{NameStr: "name-cert", Listen: "127.0.0.1", Port: "0"}, AllowInsecure: true, Users: []inbound.VlessUser{{UUID: userUUID}}, XHTTPConfig: inbound.XHTTPConfig{Mode: "auto", Path: "/name-cert"}})
					require.NoError(t, err)
					require.NoError(t, in.Listen(tunnel))
					defer in.Close()
					var upPort, downPort int
					var upCount, downCount *atomic.Int32
					restlsOpts := outbound.RestlsOptions{}
					if transport == "restls" {
						upPort, upCount = restlsDownloadFront(t, tunnel, in.Address(), "test-password")
						downPort, downCount = restlsDownloadFront(t, tunnel, in.Address(), "test-password")
						restlsOpts = outbound.RestlsOptions{Password: "test-password", VersionHint: "tls13"}
					} else {
						upPort, upCount = nameCertificateFront(t, in.Address(), &tls.Config{Certificates: []tls.Certificate{upload.TLS}, NextProtos: []string{alpn}})
						downPort, downCount = nameCertificateFront(t, in.Address(), &tls.Config{Certificates: []tls.Certificate{download.TLS}, NextProtos: []string{alpn}})
					}
					input := map[string]any{"servername": "download-front.test", "port": downPort}
					name := ""
					switch scenario {
					case "override":
						name = "download-certificate.test"
						input["name-cert-verify"] = name
					case "clear":
						input["name-cert-verify"] = ""
					case "wrong name":
						name = "wrong.test"
						input["name-cert-verify"] = name
					}
					var ds outbound.XHTTPDownloadSettings
					decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
					require.NoError(t, decoder.Decode(input, &ds))
					proxy, err := outbound.NewVless(outbound.VlessOption{Name: "name-cert", Server: "127.0.0.1", Port: upPort, UUID: userUUID, TLS: true, ServerName: "upload-front.test", NameCertVerify: "upload-certificate.test", ClientFingerprint: "chrome", RestlsOpts: restlsOpts, Network: "xhttp", ALPN: []string{alpn}, XHTTPOpts: outbound.XHTTPOptions{Mode: "stream-up", Path: "/name-cert", DownloadSettings: &ds}})
					require.NoError(t, err)
					defer proxy.Close()
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					conn, err := proxy.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 80})
					if err == nil {
						defer conn.Close()
						_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
						payload := []byte("name-cert-download/" + strconv.Itoa(downPort))
						written := make(chan error, 1)
						go func() { _, err := conn.Write(payload); written <- err }()
						reply := make([]byte, len(payload))
						_, err = io.ReadFull(conn, reply)
						if err != nil {
							_ = conn.Close()
						}
						writeErr := <-written
						if err == nil {
							err = writeErr
						}
						if err == nil && string(reply) != string(payload) {
							err = fmt.Errorf("echo mismatch")
						}
					}
					if scenario == "wrong name" {
						require.Error(t, err)
						require.Zero(t, downCount.Load())
						return
					}
					require.NoError(t, err)
					require.Positive(t, upCount.Load())
					require.Positive(t, downCount.Load())
				})
			}
		}
	}
}
