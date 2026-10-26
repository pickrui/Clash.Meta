package inbound_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/transport/jls"
	"github.com/metacubex/mihomo/transport/kcptun"
	"github.com/metacubex/mihomo/transport/restls"
	"github.com/metacubex/mihomo/transport/shadowtls"

	shadowsocks "github.com/metacubex/sing-shadowsocks"
	"github.com/metacubex/sing-shadowsocks/shadowaead"
	"github.com/metacubex/sing-shadowsocks/shadowaead_2022"
	"github.com/metacubex/sing-shadowsocks/shadowstream"
	"github.com/stretchr/testify/assert"
)

var noneList = []string{shadowsocks.MethodNone}
var shadowsocksCipherLists = [][]string{noneList, shadowaead.List, shadowaead_2022.List, shadowstream.List}
var shadowsocksCipherShortLists = [][]string{noneList, shadowaead.List[:5]} // for test shadowTLS and kcptun
var shadowsocksPassword32 string
var shadowsocksPassword16 string

func init() {
	passwordBytes := make([]byte, 32)
	rand.Read(passwordBytes)
	shadowsocksPassword32 = base64.StdEncoding.EncodeToString(passwordBytes)
	shadowsocksPassword16 = base64.StdEncoding.EncodeToString(passwordBytes[:16])
}

func testInboundShadowSocks(t *testing.T, inboundOptions inbound.ShadowSocksOption, outboundOptions outbound.ShadowSocksOption, cipherLists [][]string, enableSingMux bool) {
	t.Parallel()
	for _, cipherList := range cipherLists {
		for i, cipher := range cipherList {
			enableSingMux := enableSingMux && i == 0
			cipher := cipher
			t.Run(cipher, func(t *testing.T) {
				inboundOptions, outboundOptions := inboundOptions, outboundOptions // don't modify outside options value
				inboundOptions.Cipher = cipher
				outboundOptions.Cipher = cipher
				testInboundShadowSocks0(t, inboundOptions, outboundOptions, enableSingMux)
			})
		}
	}
}

func testInboundShadowSocks0(t *testing.T, inboundOptions inbound.ShadowSocksOption, outboundOptions outbound.ShadowSocksOption, enableSingMux bool) {
	t.Parallel()
	password := shadowsocksPassword32
	if strings.Contains(inboundOptions.Cipher, "-128-") {
		password = shadowsocksPassword16
	}
	inboundOptions.BaseOption = inbound.BaseOption{
		NameStr: "shadowsocks_inbound",
		Listen:  "127.0.0.1",
		Port:    "0",
	}
	inboundOptions.Password = password
	in, err := inbound.NewShadowSocks(&inboundOptions)
	if !assert.NoError(t, err) {
		return
	}

	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()

	err = in.Listen(tunnel)
	if !assert.NoError(t, err) {
		return
	}
	defer in.Close()

	addrPort, err := netip.ParseAddrPort(in.Address())
	if !assert.NoError(t, err) {
		return
	}

	outboundOptions.Name = "shadowsocks_outbound"
	outboundOptions.Server = addrPort.Addr().String()
	outboundOptions.Port = int(addrPort.Port())
	outboundOptions.Password = password
	outboundOptions.DialerForAPI = tunnel.NewDialer()
	outboundOptions.TunnelForAPI = tunnel

	out, err := outbound.NewShadowSocks(outboundOptions)
	if !assert.NoError(t, err) {
		return
	}
	defer out.Close()

	tunnel.DoTest(t, out)

	if enableSingMux {
		testSingMux(t, tunnel, out)
	}
}

func TestInboundShadowSocks_Basic(t *testing.T) {
	inboundOptions := inbound.ShadowSocksOption{}
	outboundOptions := outbound.ShadowSocksOption{}
	testInboundShadowSocks(t, inboundOptions, outboundOptions, shadowsocksCipherLists, true)
}

func testInboundShadowSocksUTLS(t *testing.T, inboundOptions inbound.ShadowSocksOption, outboundOptions outbound.ShadowSocksOption, enableSingMux bool) {
	t.Parallel()
	t.Run("Conn", func(t *testing.T) {
		inboundOptions, outboundOptions := inboundOptions, outboundOptions // don't modify outside options value
		testInboundShadowSocks(t, inboundOptions, outboundOptions, shadowsocksCipherShortLists, enableSingMux)
	})
	t.Run("UConn", func(t *testing.T) {
		inboundOptions, outboundOptions := inboundOptions, outboundOptions // don't modify outside options value
		outboundOptions.ClientFingerprint = "chrome"
		testInboundShadowSocks(t, inboundOptions, outboundOptions, shadowsocksCipherShortLists, enableSingMux)
	})
}

func TestInboundShadowSocks_ShadowTlsv1(t *testing.T) {
	inboundOptions := inbound.ShadowSocksOption{
		ShadowTLS: inbound.ShadowTLS{
			Enable:    true,
			Version:   1,
			Handshake: inbound.ShadowTLSHandshakeOptions{Dest: net.JoinHostPort(realityDest, "443")},
		},
	}
	outboundOptions := outbound.ShadowSocksOption{
		Plugin:     shadowtls.Mode,
		PluginOpts: map[string]any{"host": realityDest, "fingerprint": tlsFingerprint, "version": 1},
	}
	testInboundShadowSocksUTLS(t, inboundOptions, outboundOptions, true)
}

func TestInboundShadowSocks_ShadowTlsv2(t *testing.T) {
	inboundOptions := inbound.ShadowSocksOption{
		ShadowTLS: inbound.ShadowTLS{
			Enable:    true,
			Version:   2,
			Password:  shadowsocksPassword16,
			Handshake: inbound.ShadowTLSHandshakeOptions{Dest: net.JoinHostPort(realityDest, "443")},
		},
	}
	outboundOptions := outbound.ShadowSocksOption{
		Plugin:     shadowtls.Mode,
		PluginOpts: map[string]any{"host": realityDest, "password": shadowsocksPassword16, "fingerprint": tlsFingerprint, "version": 2},
	}
	outboundOptions.PluginOpts["alpn"] = []string{"http/1.1"} // shadowtls v2 work confuse with http/2 server, so we set alpn to http/1.1 to pass the test
	testInboundShadowSocksUTLS(t, inboundOptions, outboundOptions, true)
}

func TestInboundShadowSocks_ShadowTlsv3(t *testing.T) {
	inboundOptions := inbound.ShadowSocksOption{
		ShadowTLS: inbound.ShadowTLS{
			Enable:    true,
			Version:   3,
			Users:     []inbound.ShadowTLSUser{{Name: "test", Password: shadowsocksPassword16}},
			Handshake: inbound.ShadowTLSHandshakeOptions{Dest: net.JoinHostPort(realityDest, "443")},
		},
	}
	outboundOptions := outbound.ShadowSocksOption{
		Plugin:     shadowtls.Mode,
		PluginOpts: map[string]any{"host": realityDest, "password": shadowsocksPassword16, "fingerprint": tlsFingerprint, "version": 3},
	}
	testInboundShadowSocksUTLS(t, inboundOptions, outboundOptions, true)
}

func TestInboundShadowSocks_Restls_tls12(t *testing.T) {
	inboundOptions := inbound.ShadowSocksOption{
		ResTLS: inbound.ResTLS{
			Enable:   true,
			Dest:     net.JoinHostPort(realityDest, "443"),
			Password: shadowsocksPassword16,
		},
	}
	outboundOptions := outbound.ShadowSocksOption{
		Plugin:     restls.Mode,
		PluginOpts: map[string]any{"host": realityDest, "password": shadowsocksPassword16, "fingerprint": tlsFingerprint, "version-hint": "tls12", "force-tls12": true},
	}
	testInboundShadowSocks(t, inboundOptions, outboundOptions, shadowsocksCipherShortLists, false)
}

func TestInboundShadowSocks_Restls_tls13(t *testing.T) {
	inboundOptions := inbound.ShadowSocksOption{
		ResTLS: inbound.ResTLS{
			Enable:   true,
			Dest:     net.JoinHostPort(realityDest, "443"),
			Password: shadowsocksPassword16,
		},
	}
	outboundOptions := outbound.ShadowSocksOption{
		Plugin:     restls.Mode,
		PluginOpts: map[string]any{"host": realityDest, "password": shadowsocksPassword16, "fingerprint": tlsFingerprint, "version-hint": "tls13"},
	}
	testInboundShadowSocks(t, inboundOptions, outboundOptions, shadowsocksCipherShortLists, false)
}

func TestInboundShadowSocks_JLS(t *testing.T) {
	username := "jls-user"
	password := "jls-password"
	inboundOptions := inbound.ShadowSocksOption{
		JLSConfig: inbound.JLSConfig{
			Enable: true,
			Users:  []inbound.JLSUser{{Username: username, Password: password}},
			SNI:    realityDest,
			Dest:   net.JoinHostPort(realityDest, "443"),
		},
	}
	outboundOptions := outbound.ShadowSocksOption{
		Plugin: jls.Mode,
		PluginOpts: map[string]any{
			"host":     realityDest,
			"username": username,
			"password": password,
		},
	}
	testInboundShadowSocksUTLS(t, inboundOptions, outboundOptions, false)
}

func TestInboundShadowSocks_SimpleObfs_Http(t *testing.T) {
	inboundOptions := inbound.ShadowSocksOption{
		SimpleObfs: inbound.SimpleObfs{
			Enable: true,
			Mode:   "http",
		},
	}
	outboundOptions := outbound.ShadowSocksOption{
		Plugin:     "obfs",
		PluginOpts: map[string]any{"mode": "http", "host": realityDest},
	}
	testInboundShadowSocks(t, inboundOptions, outboundOptions, shadowsocksCipherShortLists, false)
}

func TestInboundShadowSocks_SimpleObfs_Tls(t *testing.T) {
	inboundOptions := inbound.ShadowSocksOption{
		SimpleObfs: inbound.SimpleObfs{
			Enable: true,
			Mode:   "tls",
		},
	}
	outboundOptions := outbound.ShadowSocksOption{
		Plugin:     "obfs",
		PluginOpts: map[string]any{"mode": "tls", "host": realityDest},
	}
	testInboundShadowSocks(t, inboundOptions, outboundOptions, shadowsocksCipherShortLists, false)
}

func TestInboundShadowSocks_KcpTun(t *testing.T) {
	t.Run("invalid connection count", func(t *testing.T) {
		client, err := outbound.NewShadowSocks(outbound.ShadowSocksOption{
			Name: "invalid-kcptun", Server: "127.0.0.1", Port: 1,
			Cipher: "none", Plugin: kcptun.Mode, PluginOpts: map[string]any{"conn": -1},
		})
		if client != nil {
			_ = client.Close()
		}
		if err == nil || !strings.Contains(err.Error(), "conn must not be negative") {
			t.Fatalf("invalid connection count was not rejected: %v", err)
		}
	})
	if winGo120 {
		t.Skip("skip kcptun test on windows go1.20")
	}
	inboundOptions := inbound.ShadowSocksOption{
		KcpTun: inbound.KcpTun{
			Enable: true,
			Key:    shadowsocksPassword16,
		},
	}
	outboundOptions := outbound.ShadowSocksOption{
		Plugin:     kcptun.Mode,
		PluginOpts: map[string]any{"key": shadowsocksPassword16},
	}
	testInboundShadowSocks(t, inboundOptions, outboundOptions, shadowsocksCipherShortLists, false)
}

func TestKcpTunClientClose(t *testing.T) {
	t.Parallel()
	for _, autoExpire := range []int{0, 1} {
		t.Run(fmt.Sprintf("autoexpire=%d", autoExpire), func(t *testing.T) {
			t.Parallel()
			sink, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer sink.Close()
			client := kcptun.NewClient(kcptun.Config{Conn: 2, AutoExpire: autoExpire})
			defer client.Close()
			var sockets []net.PacketConn
			dial := func(context.Context) (net.PacketConn, net.Addr, error) {
				pc, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err == nil {
					sockets = append(sockets, pc)
					t.Cleanup(func() { _ = pc.Close() })
				}
				return pc, sink.LocalAddr(), err
			}
			for generation := range 2 {
				if generation > 0 && autoExpire > 0 {
					time.Sleep(time.Second + time.Millisecond)
				}
				for range 2 {
					stream, err := client.OpenStream(t.Context(), dial)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = stream.Close() })
				}
			}
			want := 2
			if autoExpire > 0 {
				want = 4
			}
			if len(sockets) != want {
				t.Fatalf("expected %d active and retired sockets, got %d", want, len(sockets))
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			for i, pc := range sockets {
				if err := pc.SetReadDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
					t.Errorf("socket %d survives client close: %v", i, err)
				}
			}
			if stream, err := client.OpenStream(t.Context(), dial); err == nil {
				_ = stream.Close()
				t.Error("closed client opened a new stream")
			}
		})
	}
	t.Run("cancel pending dial", func(t *testing.T) {
		t.Parallel()
		client := kcptun.NewClient(kcptun.Config{})
		defer client.Close()
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		started, result := make(chan struct{}), make(chan error, 1)
		go func() {
			_, err := client.OpenStream(ctx, func(ctx context.Context) (net.PacketConn, net.Addr, error) {
				close(started)
				<-ctx.Done()
				return nil, nil, ctx.Err()
			})
			result <- err
		}()
		<-started
		_ = client.Close()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Errorf("pending dial not canceled by close: %v", err)
		}
	})
}
