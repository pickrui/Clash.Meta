package httpmask

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/metacubex/http"
)

type interruptedPullConn struct {
	net.Conn
	poll   bool
	before bool
	writes int
}

func (c *interruptedPullConn) Write(p []byte) (int, error) {
	c.writes++
	if c.writes == 1 {
		return c.Conn.Write(p)
	}
	cut := bytes.Index(p, []byte("\r\n")) + 2
	if !c.before {
		cut += 3
		if c.poll {
			cut = len(p) - 2
		}
	}
	n, err := c.Conn.Write(p[:cut])
	_ = c.Conn.Close()
	if err != nil {
		return n, err
	}
	return n, io.ErrUnexpectedEOF
}

func TestInterruptedPullPreservesByteStream(t *testing.T) {
	for _, tt := range []struct {
		name   string
		client *splitCodec
		server sessionCodec
		before bool
	}{
		{"stream/before-delivery", &splitStreamCodec, streamCodec, true},
		{"stream/after-delivery", &splitStreamCodec, streamCodec, false},
		{"poll/before-delivery", &splitPollCodec, pollCodec, true},
		{"poll/after-delivery", &splitPollCodec, pollCodec, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			const token = "partial-frame-replay"
			want := []byte("abcdef")
			app, backend := newHalfPipe()
			server := NewTunnelServer(TunnelServerOptions{})
			server.sessionAdd(token, backend)
			ctx, cancel := context.WithCancel(context.Background())
			var mu sync.Mutex
			var sockets []net.Conn
			var workers sync.WaitGroup
			var pulls atomic.Int32
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.Method != http.MethodGet {
					return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(nil)), Request: req}, nil
				}
				number := pulls.Add(1)
				front, back := net.Pipe()
				_ = front.SetDeadline(time.Now().Add(3 * time.Second))
				_ = back.SetDeadline(time.Now().Add(3 * time.Second))
				mu.Lock()
				sockets = append(sockets, front, back)
				mu.Unlock()
				var response net.Conn = back
				if number == 1 {
					response = &interruptedPullConn{Conn: back, poll: tt.server.poll, before: tt.before}
				}
				workers.Add(1)
				go func() {
					defer workers.Done()
					_, _, _ = server.pull(response, token, tt.server)
				}()
				return http.ReadResponse(bufio.NewReader(front), req)
			})}
			conn := &splitConn{queuedConn: newQueuedConn(), codec: tt.client, readiness: newTunnelReadiness(), ctx: ctx, cancel: cancel,
				client: client, pullURL: "http://fixture.invalid/stream?token=" + token, closeURL: "http://fixture.invalid/close", headerHost: "fixture.invalid"}
			t.Cleanup(func() {
				_ = conn.Close()
				server.sessionClose(token)
				_ = app.Close()
				_ = backend.Close()
				mu.Lock()
				for _, socket := range sockets {
					_ = socket.Close()
				}
				mu.Unlock()
				workers.Wait()
			})
			workers.Add(1)
			go func() {
				defer workers.Done()
				_, _ = app.Write(want)
				_ = app.CloseWrite()
			}()
			workers.Add(1)
			go func() { defer workers.Done(); conn.pullLoop() }()
			type result struct {
				data []byte
				err  error
			}
			done := make(chan result, 1)
			workers.Add(1)
			go func() { defer workers.Done(); data, err := io.ReadAll(conn); done <- result{data, err} }()
			select {
			case result := <-done:
				if tt.before {
					if result.err != nil || !bytes.Equal(result.data, want) {
						t.Fatalf("pull interrupted before delivery: got %q (%v), want %q without error", result.data, result.err, want)
					}
					return
				}
				if !errors.Is(result.err, io.ErrUnexpectedEOF) {
					t.Fatalf("pull interrupted after delivery did not report failure: %q (%v)", result.data, result.err)
				}
				if len(result.data) == 0 || !bytes.HasPrefix(want, result.data) {
					t.Fatalf("failed byte stream contains replayed bytes: got %q, want a nonempty prefix of %q (%v)", result.data, want, result.err)
				}
				select {
				case <-conn.closed:
				default:
					t.Fatal("pull interrupted after delivery left the connection open")
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("pull did not finish, requests=%d", pulls.Load())
			}
		})
	}
}

func TestPullNonRetryableBodyErrorClosesConnection(t *testing.T) {
	for _, codec := range []*splitCodec{&splitStreamCodec, &splitPollCodec} {
		t.Run(string(codec.mode), func(t *testing.T) {
			wantErr := errors.New("invalid response body")
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				body := io.Reader(bytes.NewReader(nil))
				if req.Method == http.MethodGet {
					body = iotest.ErrReader(wantErr)
				}
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(body), Request: req}, nil
			})}
			ctx, cancel := context.WithCancel(context.Background())
			conn := &splitConn{queuedConn: newQueuedConn(), codec: codec, readiness: newTunnelReadiness(), ctx: ctx, cancel: cancel,
				client: client, pullURL: "http://fixture.invalid/stream?token=body-error", closeURL: "http://fixture.invalid/close", headerHost: "fixture.invalid"}
			t.Cleanup(func() { _ = conn.Close() })
			outcome, readAny := conn.pullOnce()
			if outcome != pullStop || readAny {
				t.Fatalf("non-retryable body failure outcome=%v readAny=%v", outcome, readAny)
			}
			select {
			case <-conn.closed:
			default:
				t.Fatal("non-retryable body failure left the connection open")
			}
			data, err := io.ReadAll(conn)
			if len(data) != 0 || !errors.Is(err, wantErr) {
				t.Fatalf("read after non-retryable body failure: %q (%v)", data, err)
			}
		})
	}
}
