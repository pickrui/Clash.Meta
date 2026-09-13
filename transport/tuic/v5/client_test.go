package v5

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/tuic/internal/testutil"
	"github.com/metacubex/quic-go"
)

func TestDialContextReleasesRejectedStreamSlot(t *testing.T) {
	quicConn := testutil.StreamLimitedConn(t)
	client := &clientImpl{ClientOption: &ClientOption{MaxOpenStreams: 3}, quicConn: quicConn}
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
	quicConn := testutil.StreamLimitedConn(t)
	if err := quicConn.CloseWithError(0, "closed before dial"); err != nil {
		t.Fatal(err)
	}
	client := &clientImpl{ClientOption: &ClientOption{MaxOpenStreams: 3}, quicConn: quicConn}
	metadata := &C.Metadata{DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 443}
	conn, err := client.DialContext(context.Background(), metadata)
	if conn != nil || err == nil {
		t.Fatalf("got %v, %v", conn, err)
	}
	if got := client.OpenStreams(); got != 0 {
		t.Fatalf("closed connection leaked %d stream slots", got)
	}
}
