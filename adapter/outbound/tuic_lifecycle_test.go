package outbound

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

func TestTuicCloseRejectsTCPAndUDP(t *testing.T) {
	for _, token := range []string{"", "fixture-token"} {
		node, err := NewTuic(TuicOption{
			Name: "closed", Server: "127.0.0.1", Port: 443, Token: token,
			UUID: "9f3fe162-0d26-475b-9f8c-7f121923206a", Password: "fixture",
		})
		require.NoError(t, err)
		node.dialer = tuicOfflineDialer{}
		require.NoError(t, node.Close())
		require.NoError(t, node.Close())
		metadata := &C.Metadata{DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 443}
		_, err = node.DialContext(context.Background(), metadata)
		require.ErrorIs(t, err, net.ErrClosed)
		_, err = node.ListenPacketContext(context.Background(), metadata)
		require.ErrorIs(t, err, net.ErrClosed)
	}
}

type tuicOfflineDialer struct{}

func (tuicOfflineDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("unexpected TUIC dial in closed-node fixture")
}

func (tuicOfflineDialer) ListenPacket(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
	return nil, errors.New("unexpected TUIC packet socket in closed-node fixture")
}
