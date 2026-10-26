package dialer

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
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

func TestTFOCloseDuringHandshake(t *testing.T) {
	conn, _ := dialTFO(context.Background(), net.Dialer{}, "tcp", "unused")
	lazy := conn.(*tfoConn)
	t.Cleanup(func() { _ = lazy.Close() })
	connected, peer := net.Pipe()
	t.Cleanup(func() { _ = connected.Close(); _ = peer.Close() })
	started, release := make(chan struct{}), make(chan struct{})
	lazy.dialFn = func(context.Context, []byte) (net.Conn, error) {
		close(started)
		<-release
		return connected, nil
	}
	done := make(chan error, 1)
	go func() { _, err := lazy.Write([]byte("hello")); done <- err }()
	<-started
	_ = lazy.Close()
	close(release)
	if err := <-done; !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("write after close: %v", err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("late connection leaked: %v", err)
	}
}

func TestTFOConcurrentFirstWrites(t *testing.T) {
	conn, _ := dialTFO(context.Background(), net.Dialer{}, "tcp", "unused")
	lazy := conn.(*tfoConn)
	t.Cleanup(func() { _ = lazy.Close() })
	connected, peer := net.Pipe()
	t.Cleanup(func() { _ = connected.Close(); _ = peer.Close() })
	_ = connected.SetDeadline(time.Now().Add(2 * time.Second))
	var dials atomic.Int32
	lazy.dialFn = func(_ context.Context, data []byte) (net.Conn, error) {
		dials.Add(1)
		_, err := connected.Write(data)
		return connected, err
	}
	const writers = 8
	done := make(chan error, writers)
	for range writers {
		go func() { _, err := lazy.Write([]byte("x")); done <- err }()
	}
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(peer, make([]byte, writers)); err != nil {
		t.Fatal(err)
	}
	for range writers {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("concurrent writer did not finish")
		}
	}
	if count := dials.Load(); count != 1 {
		t.Fatalf("concurrent writes dialed %d times", count)
	}
}

func TestTFOHandshakeWakesReaders(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "connected", true: "failed"}[failed], func(t *testing.T) {
			conn, _ := dialTFO(context.Background(), net.Dialer{}, "tcp", "unused")
			lazy := conn.(*tfoConn)
			t.Cleanup(func() { _ = lazy.Close() })
			connected, peer := net.Pipe()
			t.Cleanup(func() { _ = connected.Close(); _ = peer.Close() })
			failure := errors.New("handshake failed")
			var dials atomic.Int32
			lazy.dialFn = func(context.Context, []byte) (net.Conn, error) {
				dials.Add(1)
				if failed {
					return nil, failure
				}
				return connected, nil
			}
			const readers = 16
			started, done := make(chan struct{}, readers), make(chan error, readers)
			for range readers {
				go func() {
					started <- struct{}{}
					_, err := lazy.Read(make([]byte, 1))
					done <- err
				}()
			}
			for range readers {
				<-started
			}
			_, err := lazy.Write([]byte("hello"))
			if failed {
				if !errors.Is(err, failure) {
					t.Fatal(err)
				}
				if _, err = lazy.Write([]byte("retry")); !errors.Is(err, failure) {
					t.Fatal(err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			_ = peer.Close()
			for range readers {
				select {
				case err := <-done:
					if failed && !errors.Is(err, failure) || !failed && !errors.Is(err, io.EOF) {
						t.Fatalf("read after handshake: %v", err)
					}
				case <-time.After(time.Second):
					t.Fatal("reader was not released")
				}
			}
			if dials.Load() != 1 {
				t.Fatal("failed early data was retried")
			}
		})
	}
}

func TestTFOHandshakeDeadlines(t *testing.T) {
	t.Run("read before first write", func(t *testing.T) {
		conn, _ := dialTFO(context.Background(), net.Dialer{}, "tcp", "unused")
		lazy := conn.(*tfoConn)
		t.Cleanup(func() { _ = lazy.Close() })
		_ = lazy.SetReadDeadline(time.Now())
		if _, err := lazy.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
		_ = lazy.SetReadDeadline(time.Time{})
		connected, peer := net.Pipe()
		t.Cleanup(func() { _ = peer.Close() })
		lazy.dialFn = func(context.Context, []byte) (net.Conn, error) { return connected, nil }
		_ = lazy.SetWriteDeadline(time.Now())
		if _, err := lazy.Write([]byte("expired")); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
		_ = lazy.SetWriteDeadline(time.Time{})
		if _, err := lazy.Write([]byte("hello")); err != nil {
			t.Fatal(err)
		}
		_ = lazy.SetReadDeadline(time.Now())
		if _, err := lazy.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
	})
	t.Run("write during handshake", func(t *testing.T) {
		conn, _ := dialTFO(context.Background(), net.Dialer{}, "tcp", "unused")
		lazy := conn.(*tfoConn)
		t.Cleanup(func() { _ = lazy.Close() })
		started := make(chan struct{})
		lazy.dialFn = func(ctx context.Context, _ []byte) (net.Conn, error) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		done := make(chan error, 1)
		go func() { _, err := lazy.Write([]byte("hello")); done <- err }()
		<-started
		_ = lazy.SetWriteDeadline(time.Now())
		select {
		case err := <-done:
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("write deadline did not cancel pending handshake")
		}
	})
}
