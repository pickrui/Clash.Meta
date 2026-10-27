package httpmask

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/http/httputil"
)

type bodyWriteSignalConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (c *bodyWriteSignalConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Write(p)
}

func TestBodyConnCloseInterruptsBlockedWriter(t *testing.T) {
	for _, operation := range []string{"write", "close-write", "close"} {
		t.Run(operation, func(t *testing.T) {
			left, peer := net.Pipe()
			raw := &bodyWriteSignalConn{Conn: left, started: make(chan struct{})}
			writer := bufio.NewWriter(raw)
			conn := &bodyConn{Conn: raw, reader: httputil.NewChunkedReader(bufio.NewReader(raw)),
				writer: httputil.NewChunkedWriter(writer), tail: writer, flush: writer.Flush}
			var workers sync.WaitGroup
			t.Cleanup(func() { _ = left.Close(); _ = peer.Close(); workers.Wait() })
			wrote := make(chan error, 1)
			workers.Add(1)
			go func() {
				defer workers.Done()
				switch operation {
				case "close-write":
					wrote <- conn.CloseWrite()
				case "close":
					wrote <- conn.Close()
				default:
					_, err := conn.Write([]byte("blocked"))
					wrote <- err
				}
			}()
			select {
			case <-raw.started:
			case <-time.After(time.Second):
				t.Fatal("writer did not reach the physical connection")
			}
			read := make(chan error, 1)
			workers.Add(1)
			go func() { defer workers.Done(); _, err := conn.Read(make([]byte, 1)); read <- err }()
			closed := make(chan error, 1)
			workers.Add(1)
			go func() { defer workers.Done(); closed <- conn.Close() }()
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Error("Close did not cancel the blocked writer")
			}
			_ = left.Close()
			for name, done := range map[string]<-chan error{"write": wrote, "read": read} {
				select {
				case err := <-done:
					if err == nil || err == io.EOF {
						t.Errorf("cancelled %s returned %v", name, err)
					}
				case <-time.After(time.Second):
					t.Errorf("Close did not release %s", name)
				}
			}
		})
	}
}

func TestBodyConnGracefulClosePreservesChunks(t *testing.T) {
	for _, halfClose := range []bool{false, true} {
		name := "close"
		if halfClose {
			name = "close-write"
		}
		t.Run(name, func(t *testing.T) {
			left, peer := net.Pipe()
			_ = left.SetDeadline(time.Now().Add(time.Second))
			_ = peer.SetDeadline(time.Now().Add(time.Second))
			writer := bufio.NewWriter(left)
			conn := &bodyConn{Conn: left, reader: httputil.NewChunkedReader(bufio.NewReader(left)),
				writer: httputil.NewChunkedWriter(writer), tail: writer, flush: writer.Flush}
			var workers sync.WaitGroup
			t.Cleanup(func() { _ = left.Close(); _ = peer.Close(); workers.Wait() })
			done := make(chan error, 1)
			workers.Add(1)
			go func() {
				defer workers.Done()
				if halfClose {
					got, err := io.ReadAll(httputil.NewChunkedReader(peer))
					if err == nil && string(got) != "tail" {
						err = io.ErrUnexpectedEOF
					}
					if err == nil {
						_, err = io.WriteString(peer, "8\r\nresponse\r\n0\r\n\r\n")
					}
					done <- err
					return
				}
				got, err := io.ReadAll(peer)
				if err == nil && !bytes.Equal(got, []byte("4\r\ntail\r\n0\r\n\r\n")) {
					err = io.ErrUnexpectedEOF
				}
				done <- err
			}()
			if _, err := conn.Write([]byte("tail")); err != nil {
				t.Fatal(err)
			}
			if halfClose {
				if err := conn.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				if n, err := conn.Write([]byte("closed")); n != 0 || !errors.Is(err, io.ErrClosedPipe) {
					t.Fatalf("Write after CloseWrite = %d, %v", n, err)
				}
				got, err := io.ReadAll(conn)
				if err != nil || string(got) != "response" {
					t.Fatalf("read after CloseWrite = %q, %v", got, err)
				}
			} else if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatalf("peer did not receive complete chunked stream: %v", err)
			}
		})
	}
}
