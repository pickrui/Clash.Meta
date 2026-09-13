package inbound_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/inbound"
	LR "github.com/metacubex/mihomo/listener/restls"
	"github.com/metacubex/tls"
)

// Both fronts feed the same XHTTP session handler. Only their outer Restls
// passwords differ, so this exercises the actual upload/download TLS closures.
func restlsDownloadFront(t *testing.T, tunnel C.Tunnel, target, password string) (int, *atomic.Int32) {
	t.Helper()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var front net.Listener = raw
	if password != "" {
		front, err = LR.NewListener(raw, LC.ResTLS{Dest: realityDest, Password: password}, tunnel)
		if err != nil {
			raw.Close()
			t.Fatal(err)
		}
	}
	var active sync.Map
	var wg sync.WaitGroup
	var count atomic.Int32
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			c, err := front.Accept()
			if err != nil {
				return
			}
			active.Store(c, struct{}{})
			wg.Go(func() {
				defer active.Delete(c)
				defer c.Close()
				peer, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer peer.Close()
				count.Add(1)
				N.Relay(c, peer)
			})
		}
	}()
	t.Cleanup(func() {
		front.Close()
		<-stopped
		active.Range(func(k, _ any) bool { k.(net.Conn).Close(); return true })
		wg.Wait()
	})
	return raw.Addr().(*net.TCPAddr).Port, &count
}

func TestInboundVless_RestlsDownloadOverride(t *testing.T) {
	for _, mode := range []string{"different_passwords", "plain_upload", "plain_download"} {
		for _, alpn := range []string{"http/1.1", "h2"} {
			t.Run(mode+"/"+alpn, func(t *testing.T) {
				tunnel := &TestTunnel{HandleTCPConnFn: func(conn net.Conn, metadata *C.Metadata) {
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
					if metadata.Type == C.INNER {
						secured := tls.Server(conn, tlsConfig.Clone())
						defer secured.Close()
						_, _ = io.Copy(io.Discard, secured)
						return
					}
					if metadata.Type != C.VLESS {
						t.Errorf("unexpected protocol: %v", metadata.Type)
						return
					}
					_, _ = io.Copy(conn, conn)
				}}
				in, err := inbound.NewVless(&inbound.VlessOption{BaseOption: inbound.BaseOption{NameStr: "restls-download", Listen: "127.0.0.1", Port: "0"}, AllowInsecure: true, Users: []inbound.VlessUser{{UUID: userUUID}}, XHTTPConfig: inbound.XHTTPConfig{Mode: "auto", Path: "/restls"}})
				if err != nil {
					t.Fatal(err)
				}
				if err := in.Listen(tunnel); err != nil {
					t.Fatal(err)
				}
				defer in.Close()
				uploadPassword, downloadPassword := "upload-password", "download-password"
				if mode == "plain_upload" {
					uploadPassword = ""
				}
				if mode == "plain_download" {
					downloadPassword = ""
				}
				uploadPort, uploadCount := restlsDownloadFront(t, tunnel, in.Address(), uploadPassword)
				downloadPort, downloadCount := restlsDownloadFront(t, tunnel, in.Address(), downloadPassword)
				uploadTLS, downloadTLS := uploadPassword != "", downloadPassword != ""
				uploadOpts, downloadOpts := outbound.RestlsOptions{}, outbound.RestlsOptions{}
				if uploadTLS {
					uploadOpts = outbound.RestlsOptions{Password: uploadPassword, VersionHint: "tls13"}
				}
				if downloadTLS {
					downloadOpts = outbound.RestlsOptions{Password: downloadPassword, VersionHint: "tls13"}
				}
				fingerprint := "firefox"
				proxy, err := outbound.NewVless(outbound.VlessOption{Name: "restls-download", Server: "127.0.0.1", Port: uploadPort, UUID: userUUID, TLS: uploadTLS, ServerName: realityDest, Fingerprint: tlsFingerprint, ClientFingerprint: "chrome", RestlsOpts: uploadOpts, Network: "xhttp", ALPN: []string{alpn}, XHTTPOpts: outbound.XHTTPOptions{Mode: "stream-up", Path: "/restls", DownloadSettings: &outbound.XHTTPDownloadSettings{Port: &downloadPort, TLS: &downloadTLS, RestlsOpts: &downloadOpts, ClientFingerprint: &fingerprint}}})
				if err != nil {
					t.Fatal(err)
				}
				defer proxy.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				conn, err := proxy.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 80})
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
				for range 2 {
					data := bytes.Repeat([]byte("independent-restls-download"), 128)
					written := make(chan error, 1)
					go func() { _, err := conn.Write(data); written <- err }()
					response := make([]byte, len(data))
					if _, err := io.ReadFull(conn, response); err != nil {
						t.Fatal(err)
					}
					if err := <-written; err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(data, response) {
						t.Fatal("XHTTP corrupted payload")
					}
				}
				if uploadCount.Load() == 0 || downloadCount.Load() == 0 {
					t.Fatal("separate upload/download endpoints were not used")
				}
			})
		}
	}
}
