package httpmask

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	http "github.com/metacubex/http"
)

func TestPollPullSurvivesLongResponse(t *testing.T) {
	for _, finish := range []string{"eof", "close"} {
		t.Run(finish, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				reader, writer := io.Pipe()
				defer reader.Close()
				defer writer.Close()
				var requestContext context.Context
				var pulls int
				client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					if req.Method == http.MethodPost {
						return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
					}
					pulls++
					if pulls > 1 {
						return nil, fmt.Errorf("unexpected repeated pull")
					}
					requestContext = req.Context()
					// Match HTTP transport cancellation, including pending response body reads.
					context.AfterFunc(req.Context(), func() {
						_ = writer.CloseWithError(req.Context().Err())
					})
					trailer := make(http.Header)
					trailer.Set(tunnelStreamEOFHeader, "1")
					return &http.Response{StatusCode: http.StatusOK, Body: reader, Trailer: trailer}, nil
				})}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				conn := &pollConn{
					queuedConn: newQueuedConn(), readiness: newTunnelReadiness(),
					ctx: ctx, cancel: cancel, client: client,
					pullURL:    "http://fixture.invalid/stream?token=session",
					closeURL:   "http://fixture.invalid/api/v1/upload?token=session&close=1",
					headerHost: "fixture.invalid", auth: newTunnelAuth("", 0),
				}
				defer conn.Close()
				done := make(chan struct{})
				go func() { defer close(done); conn.pullLoop() }()
				synctest.Wait()

				// The same active response must survive beyond the old 30-second limit.
				for i := range 5 {
					time.Sleep(10 * time.Second)
					payload := fmt.Sprintf("payload-%d", i)
					line := base64.StdEncoding.EncodeToString([]byte(payload)) + "\n"
					if _, err := io.WriteString(writer, line); err != nil {
						t.Fatalf("write chunk %d: %v", i, err)
					}
					got := make([]byte, len(payload))
					if _, err := io.ReadFull(conn, got); err != nil {
						t.Fatalf("read chunk %d: %v", i, err)
					}
					if string(got) != payload {
						t.Fatalf("chunk %d = %q, want %q", i, got, payload)
					}
				}
				synctest.Wait()
				if pulls != 1 || requestContext.Err() != nil {
					t.Fatalf("active response restarted or cancelled: pulls=%d err=%v", pulls, requestContext.Err())
				}
				var wantErr error = io.EOF
				if finish == "close" {
					_ = conn.Close()
					wantErr = io.ErrClosedPipe
				} else {
					_ = writer.Close()
				}
				<-done
				if !errors.Is(requestContext.Err(), context.Canceled) {
					t.Fatalf("request not released after %s: %v", finish, requestContext.Err())
				}
				var one [1]byte
				if n, err := conn.Read(one[:]); n != 0 || !errors.Is(err, wantErr) {
					t.Fatalf("read after %s = (%d, %v), want %v", finish, n, err, wantErr)
				}
			})
		})
	}
}
