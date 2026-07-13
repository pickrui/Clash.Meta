package dialer

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestDualStackDialContextClosesFallbackWhenPrimaryWins(t *testing.T) {
	fallback, fallbackPeer := net.Pipe()
	primary, primaryPeer := net.Pipe()
	t.Cleanup(func() {
		_ = primary.Close()
		_ = primaryPeer.Close()
		_ = fallbackPeer.Close()
	})
	releasePrimary := make(chan struct{})
	fallbackReady := make(chan struct{})
	dial := func(_ context.Context, _ string, ips []netip.Addr, _ string, _ option) (net.Conn, error) {
		if ips[0].Is4() {
			<-releasePrimary
			return primary, nil
		}
		close(fallbackReady)
		return fallback, nil
	}
	done := make(chan net.Conn, 1)
	go func() {
		conn, _ := dualStackDialContext(
			context.Background(),
			dial,
			"tcp",
			[]netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")},
			"443",
			option{prefer: 4},
		)
		done <- conn
	}()

	select {
	case <-fallbackReady:
	case <-time.After(time.Second):
		t.Fatal("fallback connection was not established")
	}
	close(releasePrimary)
	select {
	case conn := <-done:
		if conn != primary {
			t.Fatal("dual-stack dial did not return the preferred connection")
		}
	case <-time.After(time.Second):
		t.Fatal("dual-stack dial did not complete")
	}
	if err := fallbackPeer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		if errors.Is(err, io.ErrClosedPipe) {
			return
		}
		t.Fatal(err)
	}
	if _, err := fallbackPeer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("fallback connection was not closed: %v", err)
	}
}
