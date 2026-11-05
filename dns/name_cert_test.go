package dns

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/trie"
	"github.com/metacubex/mihomo/internal/testutil"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
	D "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestEncryptedDNSNameCertVerify(t *testing.T) {
	cert := testutil.NewCertificate(t, "certificate.test")
	untrusted := testutil.NewCertificate(t, "certificate.test")
	require.NoError(t, ca.AddCertificate(cert.RootPEM))
	t.Cleanup(ca.ResetCertificate)
	previousHosts := resolver.DefaultHosts
	resolver.DefaultHosts = resolver.NewHosts(trie.New[resolver.HostValue]())
	require.NoError(t, resolver.DefaultHosts.Insert("front.test", resolver.HostValue{IPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}))
	t.Cleanup(func() { resolver.DefaultHosts = previousHosts })
	for _, protocol := range []string{"tls", "https", "quic"} {
		for _, scenario := range []string{"valid", "wrong name", "untrusted", "default SNI", "skip cannot bypass"} {
			t.Run(protocol+"/"+scenario, func(t *testing.T) {
				serverCert := cert
				if scenario == "untrusted" {
					serverCert = untrusted
				}
				address, seen := nameDNSServer(t, protocol, serverCert.TLS)
				params := map[string]string{"name-cert-verify": "certificate.test"}
				switch scenario {
				case "wrong name":
					params["name-cert-verify"] = "wrong.test"
				case "skip cannot bypass":
					params["name-cert-verify"] = "wrong.test"
					params["skip-cert-verify"] = "true"
				case "default SNI":
					delete(params, "name-cert-verify")
				}
				clients := transform([]NameServer{{Net: protocol, Addr: address, Params: params}}, nil)
				require.Len(t, clients, 1)
				client := clients[0]
				closer, ok := client.(io.Closer)
				require.True(t, ok)
				defer closer.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
				defer cancel()
				query := new(D.Msg).SetQuestion("answer.test.", D.TypeA)
				reply, err := client.ExchangeContext(ctx, query)
				if scenario != "valid" {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)
				require.True(t, reply.Response)
				require.Equal(t, query.Id, reply.Id)
				require.Equal(t, query.Question, reply.Question)
				select {
				case sni := <-seen:
					require.Equal(t, "front.test", sni)
				case <-ctx.Done():
					t.Fatal("server did not observe SNI")
				}
			})
		}
	}
}

func nameDNSReply(packet []byte) ([]byte, error) {
	query := new(D.Msg)
	if err := query.Unpack(packet); err != nil {
		return nil, err
	}
	return new(D.Msg).SetReply(query).Pack()
}

func nameDNSServer(t *testing.T, protocol string, certificate tls.Certificate) (string, <-chan string) {
	t.Helper()
	seen := make(chan string, 16)
	config := &tls.Config{Certificates: []tls.Certificate{certificate}, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) { seen <- hello.ServerName; return nil, nil }}
	if protocol == "quic" {
		config.NextProtos = []string{NextProtoDQ}
		listener, err := quic.ListenAddr("127.0.0.1:0", config, nil)
		require.NoError(t, err)
		ctx, cancel := context.WithCancel(context.Background())
		var workers sync.WaitGroup
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				conn, err := listener.Accept(ctx)
				if err != nil {
					return
				}
				workers.Go(func() {
					defer conn.CloseWithError(0, "")
					stream, err := conn.AcceptStream(ctx)
					if err != nil {
						return
					}
					_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
					var size uint16
					if binary.Read(stream, binary.BigEndian, &size) != nil {
						return
					}
					packet := make([]byte, size)
					if _, err = io.ReadFull(stream, packet); err != nil {
						return
					}
					reply, err := nameDNSReply(packet)
					if err != nil {
						return
					}
					_, err = stream.Write(binary.BigEndian.AppendUint16(nil, uint16(len(reply))))
					if err != nil {
						return
					}
					if _, err = stream.Write(reply); err != nil {
						return
					}
					_ = stream.Close()
					select {
					case <-conn.Context().Done():
					case <-ctx.Done():
					}
				})
			}
		}()
		t.Cleanup(func() { cancel(); _ = listener.Close(); <-done; workers.Wait() })
		_, port, _ := net.SplitHostPort(listener.Addr().String())
		return net.JoinHostPort("front.test", port), seen
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	address := net.JoinHostPort("front.test", port)
	if protocol == "https" {
		config.NextProtos = []string{"h2", "http/1.1"}
		server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			query, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
			if err != nil {
				w.WriteHeader(400)
				return
			}
			reply, err := nameDNSReply(query)
			if err != nil {
				w.WriteHeader(400)
				return
			}
			w.Header().Set("Content-Type", "application/dns-message")
			_, _ = w.Write(reply)
		})}
		done := make(chan struct{})
		go func() { defer close(done); _ = server.Serve(tls.NewListener(listener, config)) }()
		t.Cleanup(func() { _ = server.Close(); <-done })
		return "https://" + address + "/dns-query", seen
	}
	var active sync.Map
	var workers sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			active.Store(raw, struct{}{})
			workers.Go(func() {
				defer active.Delete(raw)
				defer raw.Close()
				_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
				conn := &D.Conn{Conn: tls.Server(raw, config)}
				for {
					query, err := conn.ReadMsg()
					if err != nil {
						return
					}
					if conn.WriteMsg(new(D.Msg).SetReply(query)) != nil {
						return
					}
				}
			})
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
		active.Range(func(k, _ any) bool { _ = k.(net.Conn).Close(); return true })
		workers.Wait()
	})
	return address, seen
}
