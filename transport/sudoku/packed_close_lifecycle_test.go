package sudoku

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/sudoku/crypto"
	sudokuobfs "github.com/metacubex/mihomo/transport/sudoku/obfs/sudoku"
)

type packedBlockedWriteConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

type packedEOFConn struct{ net.Conn }

func (c *packedEOFConn) Read([]byte) (int, error) { return 0, io.EOF }

type packedHalfCloseConn struct{ net.Conn }

func (c *packedHalfCloseConn) CloseWrite() error { return nil }

type packedNoDeadlineConn struct{ net.Conn }

func (c *packedNoDeadlineConn) SetWriteDeadline(time.Time) error { return nil }

func TestDirectionalPackedCloseBoundsDeadlineIgnoringTransport(t *testing.T) {
	for _, half := range []bool{false, true} {
		name := "Close"
		if half {
			name = "CloseWrite"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				left, peer := net.Pipe()
				raw := &packedNoDeadlineConn{Conn: left}
				table := sudokuobfs.NewTable("packed-no-deadline-close", "prefer_ascii")
				writer, closers := sudokuobfs.NewServerDownlinkWriter(raw, table, 100, 100, false)
				conn := newDirectionalConn(raw, raw, writer, closers...)
				var workers sync.WaitGroup
				defer func() {
					_ = left.Close()
					_ = peer.Close()
					workers.Wait()
				}()
				done := make(chan error, 1)
				workers.Add(1)
				go func() {
					defer workers.Done()
					if half {
						done <- conn.(interface{ CloseWrite() error }).CloseWrite()
					} else {
						done <- conn.Close()
					}
				}()
				select {
				case err := <-done:
					if err == nil {
						t.Fatal("interrupted packed control write succeeded")
					}
				case <-time.After(C.DefaultTCPTimeout + time.Second):
					t.Fatal("cleanup relied on an ignored write deadline")
				}
			})
		})
	}
}

func TestDirectionalPackedCloseWriteFlushIsBounded(t *testing.T) {
	for _, relay := range []bool{false, true} {
		name := "CloseWrite"
		if relay {
			name = "Relay-RecordConn"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				left, peer := net.Pipe()
				table := sudokuobfs.NewTable("packed-half-close-budget", "prefer_ascii")
				writer, closers := sudokuobfs.NewServerDownlinkWriter(left, table, 100, 100, false)
				conn := newDirectionalConn(left, left, writer, closers...)
				var workers sync.WaitGroup
				defer func() {
					_ = left.Close()
					_ = peer.Close()
					workers.Wait()
				}()
				done := make(chan error, 1)
				workers.Add(1)
				if relay {
					record, err := crypto.NewRecordConn(conn, "chacha20-poly1305", make([]byte, 32), make([]byte, 32))
					if err != nil {
						t.Fatal(err)
					}
					other, otherPeer := net.Pipe()
					defer other.Close()
					defer otherPeer.Close()
					go func() {
						defer workers.Done()
						N.Relay(&packedEOFConn{Conn: other}, record)
						done <- nil
					}()
				} else {
					go func() {
						defer workers.Done()
						done <- conn.(interface{ CloseWrite() error }).CloseWrite()
					}()
				}
				select {
				case err := <-done:
					if !relay && !errors.Is(err, os.ErrDeadlineExceeded) && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
						t.Fatalf("CloseWrite error = %v", err)
					}
				case <-time.After(C.DefaultTCPTimeout + time.Second):
					t.Fatal("half-close cleanup remained blocked beyond the control-write budget")
				}
				if _, err := conn.Read(make([]byte, 1)); err == nil {
					t.Fatal("failed half-close left the read side open")
				}
			})
		})
	}
}

func TestDirectionalPackedCloseWritePreservesReadAndClearsDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		left, peer := net.Pipe()
		raw := &packedHalfCloseConn{Conn: left}
		table := sudokuobfs.NewTable("packed-half-close-response", "prefer_ascii")
		writer, closers := sudokuobfs.NewServerDownlinkWriter(raw, table, 100, 100, false)
		conn := newDirectionalConn(raw, raw, writer, closers...)
		var workers sync.WaitGroup
		defer func() {
			_ = left.Close()
			_ = peer.Close()
			workers.Wait()
		}()
		workers.Add(1)
		go func() { defer workers.Done(); _, _ = io.Copy(io.Discard, peer) }()
		if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(C.DefaultTCPTimeout + time.Second)
		if _, err := raw.Write([]byte("next write")); err != nil {
			t.Fatalf("half-close left an expired write deadline: %v", err)
		}
		workers.Add(1)
		go func() { defer workers.Done(); _, _ = peer.Write([]byte("response")) }()
		got := make([]byte, len("response"))
		if _, err := io.ReadFull(conn, got); err != nil || string(got) != "response" {
			t.Fatalf("half-close response = %q: %v", got, err)
		}
	})
}

func (c *packedBlockedWriteConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Write(p)
}

type packedCloseControlConn struct{ net.Conn }

func (c *packedCloseControlConn) Close() error {
	_, _ = c.Conn.Write([]byte("close control frame"))
	return c.Conn.Close()
}

func TestDirectionalPackedCloseInterruptsBlockedOperations(t *testing.T) {
	for _, tt := range []struct {
		name         string
		controlWrite bool
	}{
		{"socket", false},
		{"synchronous-close-control-write", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			left, peer := net.Pipe()
			var base net.Conn = left
			if tt.controlWrite {
				base = &packedCloseControlConn{Conn: left}
			}
			raw := &packedBlockedWriteConn{Conn: base, started: make(chan struct{})}
			table := sudokuobfs.NewTable("packed-close-blocked-write", "prefer_ascii")
			writer, closers := sudokuobfs.NewServerDownlinkWriter(raw, table, 0, 0, false)
			conn := newDirectionalConn(raw, raw, writer, closers...)
			var workers sync.WaitGroup
			t.Cleanup(func() {
				_ = left.Close()
				_ = peer.Close()
				workers.Wait()
			})
			writeDone := make(chan error, 1)
			workers.Add(1)
			go func() {
				defer workers.Done()
				_, err := conn.Write(bytes.Repeat([]byte("blocked packed write"), 32))
				writeDone <- err
			}()
			select {
			case <-raw.started:
			case <-time.After(time.Second):
				t.Fatal("packed writer did not reach the underlying socket")
			}
			readDone := make(chan error, 1)
			workers.Add(1)
			go func() {
				defer workers.Done()
				_, err := conn.Read(make([]byte, 1))
				readDone <- err
			}()
			closeDone := make(chan error, 1)
			workers.Add(1)
			go func() {
				defer workers.Done()
				closeDone <- conn.Close()
			}()
			select {
			case <-closeDone:
			case <-time.After(time.Second):
				t.Fatal("Close did not interrupt the packed writer before waiting for Flush")
			}
			for name, done := range map[string]<-chan error{"read": readDone, "write": writeDone} {
				select {
				case err := <-done:
					if err == nil {
						t.Fatalf("blocked %s completed without a close error: %v", name, err)
					}
				case <-time.After(time.Second):
					t.Fatalf("Close did not unblock %s", name)
				}
			}
		})
	}
}

func TestDirectionalPackedCloseFlushIsBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		left, peer := net.Pipe()
		raw := &packedBlockedWriteConn{Conn: left, started: make(chan struct{})}
		table := sudokuobfs.NewTable("packed-close-own-flush", "prefer_ascii")
		writer, closers := sudokuobfs.NewServerDownlinkWriter(raw, table, 100, 100, false)
		conn := newDirectionalConn(raw, raw, writer, closers...)
		var workers sync.WaitGroup
		defer func() {
			_ = raw.Conn.Close()
			_ = peer.Close()
			workers.Wait()
		}()
		readDone := make(chan error, 1)
		workers.Add(1)
		go func() {
			defer workers.Done()
			_, err := conn.Read(make([]byte, 1))
			readDone <- err
		}()
		closeDone := make(chan error, 1)
		workers.Add(1)
		go func() {
			defer workers.Done()
			closeDone <- conn.Close()
		}()
		select {
		case <-raw.started:
		case err := <-closeDone:
			t.Fatalf("Close skipped its packed flush: %v", err)
		case <-time.After(C.DefaultTCPTimeout + time.Second):
			t.Fatal("Close neither completed nor reached the packed flush")
		}
		select {
		case err := <-closeDone:
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("Close error = %v, want the flush deadline error", err)
			}
		case <-time.After(C.DefaultTCPTimeout + time.Second):
			t.Fatal("Close's own packed Flush remained blocked beyond the close budget")
		}
		select {
		case err := <-readDone:
			if err == nil {
				t.Fatal("blocked Read succeeded after Close")
			}
		case <-time.After(time.Second):
			t.Fatal("Close did not unblock Read after its flush budget")
		}
	})
}
