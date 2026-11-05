package tuic

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/transport/tuic/internal/testutil"
	"github.com/metacubex/mihomo/transport/tuic/types"
	"github.com/metacubex/quic-go"
	"github.com/stretchr/testify/require"
)

func testPoolClient(version int, mode UdpRelayMode, dial DialFunc) *PoolClient {
	if version == 4 {
		return NewPoolClientV4(&ClientOptionV4{
			Token: [32]byte{1}, RequestTimeout: 3 * time.Second,
			MaxOpenStreams: 4, MaxUdpRelayPacketSize: 1200, UdpRelayMode: mode,
		}, dial)
	}
	return NewPoolClientV5(&ClientOptionV5{
		Uuid: [16]byte{1}, Password: "fixture",
		MaxOpenStreams: 4, MaxUdpRelayPacketSize: 1200, UdpRelayMode: mode,
	}, dial)
}

func TestPoolCloseStopsTCPAndUDPTransports(t *testing.T) {
	for _, version := range []int{4, 5} {
		for _, mode := range []UdpRelayMode{QUIC, NATIVE} {
			t.Run(fmt.Sprintf("v%d/udp-%d", version, mode), func(t *testing.T) {
				serverTLS, clientTLS := testutil.TLSConfigs(t)
				packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
				require.NoError(t, err)
				t.Cleanup(func() { _ = packet.Close() })
				destination := netip.MustParseAddrPort("192.0.2.1:5353")
				var echoes sync.WaitGroup
				server, err := NewServer(&ServerOption{
					TlsConfig: serverTLS, QuicConfig: &quic.Config{EnableDatagrams: true},
					Tokens: [][32]byte{{1}}, Users: map[[16]byte]string{{1}: "fixture"},
					AuthenticationTimeout: 3 * time.Second, MaxUdpRelayPacketSize: 1200,
					HandleTcpFn: func(conn net.Conn, _ socks5.Addr, _ ...inbound.Addition) error {
						echoes.Go(func() {
							defer conn.Close()
							_, _ = io.Copy(conn, conn)
						})
						return nil
					},
					HandleUdpFn: func(_ socks5.Addr, packet C.UDPPacket, _ ...inbound.Addition) error {
						defer packet.Drop()
						_, err := packet.WriteBack(packet.Data(), net.UDPAddrFromAddrPort(destination))
						return err
					},
				}, packet)
				require.NoError(t, err)
				served := make(chan struct{})
				go func() { defer close(served); _ = server.Serve() }()
				t.Cleanup(func() { _ = server.Close(); <-served; echoes.Wait() })
				var dialCount atomic.Int32
				connections := make(chan *quic.Conn, 4)
				pool := testPoolClient(version, mode, func(ctx context.Context) (*quic.Conn, error) {
					dialCount.Add(1)
					conn, err := quic.DialAddr(ctx, packet.LocalAddr().String(), clientTLS, &quic.Config{EnableDatagrams: true, KeepAlivePeriod: time.Second})
					if err == nil {
						connections <- conn
					}
					return conn, err
				})
				t.Cleanup(pool.Close)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				metadata := &C.Metadata{DstIP: destination.Addr(), DstPort: destination.Port()}
				stream, err := pool.DialContext(ctx, metadata)
				require.NoError(t, err)
				defer stream.Close()
				require.NoError(t, stream.SetDeadline(time.Now().Add(5*time.Second)))
				_, err = stream.Write([]byte("tcp echo"))
				require.NoError(t, err)
				buf := make([]byte, len("tcp echo"))
				_, err = io.ReadFull(stream, buf)
				require.NoError(t, err)
				require.Equal(t, "tcp echo", string(buf))
				packets, err := pool.ListenPacket(ctx, metadata)
				require.NoError(t, err)
				defer packets.Close()
				require.NoError(t, packets.SetDeadline(time.Now().Add(5*time.Second)))
				_, err = packets.WriteTo([]byte("udp echo"), net.UDPAddrFromAddrPort(destination))
				require.NoError(t, err)
				n, _, err := packets.ReadFrom(buf)
				require.NoError(t, err)
				require.Equal(t, "udp echo", string(buf[:n]))
				client, err := pool.getClient(false)
				require.NoError(t, err)
				pool.Close()
				pool.Close()
				require.Error(t, (<-connections).Context().Err())
				require.Error(t, (<-connections).Context().Err())
				require.Zero(t, pool.tcpClients.Len())
				require.Zero(t, pool.udpClients.Len())
				_, err = pool.DialContext(ctx, metadata)
				require.ErrorIs(t, err, net.ErrClosed)
				_, err = pool.ListenPacket(ctx, metadata)
				require.ErrorIs(t, err, net.ErrClosed)
				_, err = client.DialContext(ctx, metadata)
				require.ErrorIs(t, err, types.ClientClosed)
				require.EqualValues(t, 2, dialCount.Load())
			})
		}
	}
}

func TestPoolCloseCancelsDialAndDiscardsLateConnections(t *testing.T) {
	for _, version := range []int{4, 5} {
		for _, udp := range []bool{false, true} {
			for _, late := range []bool{false, true} {
				t.Run(fmt.Sprintf("v%d/udp-%t/late-%t", version, udp, late), func(t *testing.T) {
					var connection *quic.Conn
					if late {
						connection = testutil.ConnectedQUIC(t, -1)
					}
					started := make(chan struct{})
					pool := testPoolClient(version, NATIVE, func(ctx context.Context) (*quic.Conn, error) {
						close(started)
						<-ctx.Done()
						if late {
							return connection, nil
						}
						return nil, ctx.Err()
					})
					t.Cleanup(pool.Close)
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					dialed := make(chan error, 1)
					go func() {
						metadata := &C.Metadata{DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 443}
						if udp {
							_, err := pool.ListenPacket(ctx, metadata)
							dialed <- err
						} else {
							_, err := pool.DialContext(ctx, metadata)
							dialed <- err
						}
					}()
					<-started
					pool.Close()
					require.ErrorIs(t, <-dialed, context.Canceled)
					if late {
						require.Error(t, connection.Context().Err())
					}
					require.Zero(t, pool.tcpClients.Len())
					require.Zero(t, pool.udpClients.Len())
				})
			}
		}
	}
}

func TestPoolDialKeepsConnectionAfterCallerCancel(t *testing.T) {
	connection := testutil.ConnectedQUIC(t, -1)
	ctx, cancel := context.WithCancel(context.Background())
	pool := testPoolClient(5, NATIVE, func(context.Context) (*quic.Conn, error) {
		cancel()
		return connection, nil
	})
	t.Cleanup(pool.Close)
	conn, err := pool.dialFn(ctx)
	require.NoError(t, err)
	require.Same(t, connection, conn)
	require.NoError(t, connection.Context().Err())
}
