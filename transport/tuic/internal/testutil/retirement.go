package testutil

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/tuic/types"
	"github.com/metacubex/quic-go"
	"github.com/stretchr/testify/require"
)

// The parent's cleanup restores grace after its parallel subtests finish.
func shortenGrace(t *testing.T, grace *time.Duration) {
	previous := *grace
	*grace = 500 * time.Millisecond
	t.Cleanup(func() { *grace = previous })
}

func CheckClientRetirement(t *testing.T, grace *time.Duration, create func(types.DialFunc) (types.Client, func())) {
	t.Helper()
	shortenGrace(t, grace)
	for _, udp := range []bool{false, true} {
		t.Run(fmt.Sprintf("udp-%t", udp), func(t *testing.T) {
			t.Parallel()
			client, retire := create(func(context.Context) (*quic.Conn, error) {
				return ConnectedQUIC(t, 10), nil
			})
			t.Cleanup(retire)
			metadata := &C.Metadata{DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 443}
			open := func() io.Closer {
				t.Helper()
				if udp {
					pc, err := client.ListenPacket(context.Background(), metadata)
					require.NoError(t, err)
					return pc
				}
				conn, err := client.DialContext(context.Background(), metadata)
				require.NoError(t, err)
				return conn
			}
			old := open()
			if !udp {
				require.NoError(t, old.Close())
			}
			retire()
			current := open()
			defer current.Close()
			require.EqualValues(t, 1, client.OpenStreams())
			if udp {
				_ = old.Close()
				pc := current.(net.PacketConn)
				require.NoError(t, pc.SetReadDeadline(time.Now().Add(10*time.Millisecond)))
				_, _, err := pc.ReadFrom(make([]byte, 64))
				require.ErrorIs(t, err, os.ErrDeadlineExceeded, "a retired UDP stream closed the replacement's input")
			}
			time.Sleep(*grace + 100*time.Millisecond)
			require.EqualValues(t, 1, client.OpenStreams(), "the old grace callback changed the replacement's stream count")
		})
	}
}

func CheckClientGraceClose(t *testing.T, grace *time.Duration, create func(types.DialFunc) (types.Client, func())) {
	t.Helper()
	shortenGrace(t, grace)
	for _, udp := range []bool{false, true} {
		t.Run(fmt.Sprintf("udp-%t", udp), func(t *testing.T) {
			t.Parallel()
			transport := ConnectedQUIC(t, 10)
			client, retire := create(func(context.Context) (*quic.Conn, error) { return transport, nil })
			t.Cleanup(retire)
			metadata := &C.Metadata{DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 443}
			var stream io.Closer
			var err error
			if udp {
				stream, err = client.ListenPacket(context.Background(), metadata)
			} else {
				stream, err = client.DialContext(context.Background(), metadata)
			}
			require.NoError(t, err)
			client.Close()
			require.NoError(t, transport.Context().Err(), "graceful close interrupted a live stream")
			require.NoError(t, stream.Close())
			require.NoError(t, stream.Close())
			require.EqualValues(t, 1, client.OpenStreams(), "closing the stream skipped its grace period")
			select {
			case <-transport.Context().Done():
			case <-time.After(*grace + time.Second):
				t.Fatal("the transport outlived its final stream's grace period")
			}
			require.Zero(t, client.OpenStreams())
		})
	}
}

func CheckGraceReleasesRetiredClient[I any, P interface {
	*I
	ListenPacket(context.Context, *C.Metadata) (net.PacketConn, error)
}, S any](t *testing.T, grace time.Duration, create func(types.DialFunc) (client P, session func() *S, retire func())) {
	transport := ConnectedQUIC(t, 10)
	collected := make(chan struct{}, 2)
	func() {
		client, session, retire := create(func(context.Context) (*quic.Conn, error) { return transport, nil })
		markCollected := func(done chan struct{}) { done <- struct{}{} }
		runtime.AddCleanup((*I)(client), markCollected, collected)
		stream, err := client.ListenPacket(context.Background(), &C.Metadata{})
		require.NoError(t, err)
		runtime.AddCleanup(session(), markCollected, collected)
		require.NoError(t, stream.Close())
		retire()
	}()
	deadline := time.Now().Add(grace / 2)
	for pending := 2; pending > 0; {
		runtime.GC()
		select {
		case <-collected:
			pending--
			continue
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("the grace timer retained a retired client or session")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
