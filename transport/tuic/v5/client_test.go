package v5

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/tuic/common"
	"github.com/metacubex/mihomo/transport/tuic/internal/testutil"
	"github.com/metacubex/mihomo/transport/tuic/types"
	"github.com/metacubex/quic-go"
)

func retirementClient(dial types.DialFunc) (types.Client, func()) {
	client := NewClient(&ClientOption{MaxOpenStreams: 10, UdpRelayMode: types.NATIVE}, true, dial)
	return client, func() { client.clientImpl.forceClose(nil, net.ErrClosed) }
}

func TestClientRetiredStreams(t *testing.T) {
	testutil.CheckClientRetirement(t, &common.StreamGrace, retirementClient)
}

func TestClientGraceClose(t *testing.T) {
	testutil.CheckClientGraceClose(t, &common.StreamGrace, retirementClient)
}

func TestDialContextReleasesRejectedStreamSlot(t *testing.T) {
	quicConn := testutil.ConnectedQUIC(t, -1)
	client := &clientImpl{ClientOption: &ClientOption{MaxOpenStreams: 3}}
	client.session.Store(&clientSession{conn: quicConn})
	metadata := &C.Metadata{DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 443}
	for attempt := 0; attempt < 5; attempt++ {
		conn, err := client.DialContext(context.Background(), metadata)
		var limit *quic.StreamLimitReachedError
		if conn != nil || !errors.As(err, &limit) {
			t.Fatalf("attempt %d: got %v, %v", attempt, conn, err)
		}
		if got := client.OpenStreams(); got != 0 {
			t.Errorf("attempt %d leaked %d stream slots", attempt, got)
		}
	}
}

func TestDialContextReleasesClosedConnectionSlot(t *testing.T) {
	quicConn := testutil.ConnectedQUIC(t, -1)
	if err := quicConn.CloseWithError(0, "closed before dial"); err != nil {
		t.Fatal(err)
	}
	client := &clientImpl{ClientOption: &ClientOption{MaxOpenStreams: 3}}
	client.session.Store(&clientSession{conn: quicConn})
	metadata := &C.Metadata{DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 443}
	conn, err := client.DialContext(context.Background(), metadata)
	if conn != nil || err == nil {
		t.Fatalf("got %v, %v", conn, err)
	}
	if got := client.OpenStreams(); got != 0 {
		t.Fatalf("closed connection leaked %d stream slots", got)
	}
}

func TestGraceDoesNotRetainRetiredClient(t *testing.T) {
	testutil.CheckGraceReleasesRetiredClient(t, common.StreamGrace, func(dial types.DialFunc) (*clientImpl, func() *clientSession, func()) {
		client := &clientImpl{ClientOption: &ClientOption{MaxOpenStreams: 10, UdpRelayMode: types.NATIVE}, udp: true, dialFn: dial}
		return client, client.session.Load, func() { client.forceClose(nil, net.ErrClosed) }
	})
}
