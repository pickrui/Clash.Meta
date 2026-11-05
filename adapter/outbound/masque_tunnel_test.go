package outbound

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/masque"
	"github.com/metacubex/mipstack"
	"github.com/metacubex/quic-go/quicvarint"
	D "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func masqueEchoTunnel(t *testing.T, option MasqueOption) *Masque {
	t.Helper()
	remote, err := mipstack.New(mipstack.Config{
		LocalAddresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}, MTU: 1280,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = remote.Close() })
	require.NoError(t, remote.Start())
	listener, err := remote.ListenTCP(context.Background(), "tcp4", netip.MustParseAddrPort("192.0.2.1:8080"))
	require.NoError(t, err)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}
	}()
	packets, err := remote.ListenUDP(context.Background(), "udp4", netip.MustParseAddrPort("192.0.2.1:5353"))
	require.NoError(t, err)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, address, err := packets.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err = packets.WriteTo(buf[:n], address); err != nil {
				return
			}
		}
	}()
	if option.RemoteDnsResolve {
		dnsPackets, err := remote.ListenUDP(context.Background(), "udp4", netip.MustParseAddrPort("192.0.2.1:5354"))
		require.NoError(t, err)
		done := make(chan struct{})
		go func() {
			defer close(done)
			buffer := make([]byte, 2048)
			for {
				n, address, err := dnsPackets.ReadFrom(buffer)
				if err != nil {
					return
				}
				query := new(D.Msg)
				if query.Unpack(buffer[:n]) != nil {
					continue
				}
				reply := new(D.Msg).SetReply(query)
				if len(query.Question) > 0 && query.Question[0].Qtype == D.TypeA {
					reply.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: query.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.1").To4()}}
				}
				data, err := reply.Pack()
				if err == nil {
					_, _ = dnsPackets.WriteTo(data, address)
				}
			}
		}()
		t.Cleanup(func() { _ = dnsPackets.Close(); <-done })
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Header.Get("cf-connect-proto") != "cf-connect-ip" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer remote.Close()
		defer r.Body.Close()
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		go func() {
			defer remote.Close()
			reader := quicvarint.NewReader(r.Body)
			for {
				kind, err := quicvarint.Read(reader)
				if err != nil {
					return
				}
				length, err := quicvarint.Read(reader)
				if err != nil || length == 0 || length > 65536 {
					return
				}
				packet := make([]byte, length)
				if _, err = io.ReadFull(reader, packet); err != nil {
					return
				}
				if kind != 0 {
					return
				}
				if _, err = remote.Write([][]byte{packet}, 0); err != nil {
					return
				}
			}
		}()
		buf := make([]byte, 65535)
		sizes := make([]int, 1)
		for {
			if _, err := remote.Read([][]byte{buf}, sizes, 0); err != nil {
				return
			}
			capsule := quicvarint.Append(nil, 0)
			capsule = quicvarint.Append(capsule, uint64(sizes[0]))
			capsule = append(capsule, buf[:sizes[0]]...)
			if _, err := w.Write(capsule); err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
	}))
	private, err := base64.StdEncoding.DecodeString(option.PrivateKey)
	require.NoError(t, err)
	key, err := x509.ParseECPrivateKey(private)
	require.NoError(t, err)
	certificates, err := masque.GenerateCert(key)
	require.NoError(t, err)
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: certificates, PrivateKey: key}}}
	server.StartTLS()
	t.Cleanup(func() { _ = remote.Close(); server.Close() })
	option.Network = "h2"
	option.Port = server.Listener.Addr().(*net.TCPAddr).Port
	node, err := NewMasque(option)
	require.NoError(t, err)
	t.Cleanup(func() { _ = node.Close() })
	return node
}

func TestMasqueLazyStackCarriesTCPAndUDP(t *testing.T) {
	base := masqueTestOption(t)
	for _, mode := range masqueTestStackModes() {
		for _, settings := range []struct {
			timeout   int
			remoteDNS bool
		}{{0, false}, {2, false}, {0, true}} {
			t.Run(fmt.Sprintf("%s/timeout-%d/dns-%v", mode, settings.timeout, settings.remoteDNS), func(t *testing.T) {
				option := base
				option.IPStack.Mode, option.HandshakeTimeout = mode, settings.timeout
				option.RemoteDnsResolve, option.Dns = settings.remoteDNS, []string{"192.0.2.1:5354"}
				option.UDP = true
				node := masqueEchoTunnel(t, option)
				require.Nil(t, node.tunDevice)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				tcpTarget := &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 8080}
				if settings.remoteDNS {
					tcpTarget.DstIP, tcpTarget.Host = netip.Addr{}, "echo.test"
				}
				conn, err := node.DialContext(ctx, tcpTarget)
				require.NoError(t, err)
				defer conn.Close()
				require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
				_, err = conn.Write([]byte("tcp echo"))
				require.NoError(t, err)
				buf := make([]byte, len("tcp echo"))
				_, err = io.ReadFull(conn, buf)
				require.NoError(t, err)
				require.Equal(t, "tcp echo", string(buf))

				device := node.tunDevice
				udpTarget := &C.Metadata{NetWork: C.UDP, DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 5353}
				if settings.remoteDNS {
					udpTarget.DstIP, udpTarget.Host = netip.Addr{}, "echo.test"
				}
				pc, err := node.ListenPacketContext(ctx, udpTarget)
				require.NoError(t, err)
				defer pc.Close()
				require.Same(t, device, node.tunDevice)
				require.NoError(t, pc.SetDeadline(time.Now().Add(5*time.Second)))
				_, err = pc.WriteTo([]byte("udp echo"), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.1:5353")))
				require.NoError(t, err)
				buf = make([]byte, 64)
				n, address, err := pc.ReadFrom(buf)
				require.NoError(t, err)
				require.Equal(t, "udp echo", string(buf[:n]))
				require.Equal(t, "192.0.2.1:5353", address.String())
				require.NoError(t, node.Close())
				_, err = node.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 8080})
				require.ErrorIs(t, err, context.Canceled)
			})
		}
	}
}
