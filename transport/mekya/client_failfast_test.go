package mekya

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptrace"
	"github.com/stretchr/testify/require"
)

type scriptedRoundTripper struct {
	mu     sync.Mutex
	calls  atomic.Int32
	bodies [][]byte
	// respond returns the response for the given call index (starting at 1).
	respond func(call int, req *http.Request) (*http.Response, error)
}

func (r *scriptedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	call := int(r.calls.Add(1))
	if req.Body != nil {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.bodies = append(r.bodies, body)
		r.mu.Unlock()
	}
	return r.respond(call, req)
}

func (r *scriptedRoundTripper) bodyLengths() []int {
	r.mu.Lock()
	defer r.mu.Unlock()
	lengths := make([]int, len(r.bodies))
	for i, body := range r.bodies {
		lengths[i] = len(body)
	}
	return lengths
}

func emptyOK() (*http.Response, error) {
	return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
}

func newScriptedClient(ctx context.Context, rt http.RoundTripper, cfg Config) *Client {
	if cfg.PollingIntervalInitial == 0 {
		cfg.PollingIntervalInitial = 1
	}
	if cfg.MaxWriteDelay == 0 {
		cfg.MaxWriteDelay = 1
	}
	return &Client{ctx: ctx, cfg: cfg, url: "https://fixture.invalid/", rt: rt}
}

func TestDialFailsFastWhenTransportUnreachable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dialErr := errors.New("connect: connection refused")
	rt := &scriptedRoundTripper{respond: func(int, *http.Request) (*http.Response, error) { return nil, dialErr }}
	client := newScriptedClient(ctx, rt, Config{})
	dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)
	defer dialCancel()
	started := time.Now()
	_, err := client.Dial(dialCtx)
	require.ErrorIs(t, err, dialErr)
	require.Less(t, time.Since(started), time.Second, "an unreachable server must fail the dial, not the caller's deadline")
	require.Eventually(t, func() bool { return rt.calls.Load() == 1 }, time.Second, time.Millisecond)
	require.Never(t, func() bool { return rt.calls.Load() > 1 }, 100*time.Millisecond, time.Millisecond,
		"a failed session must not keep polling")
}

func TestDialFailsWhenServerRejectsSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rt := &scriptedRoundTripper{respond: func(int, *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 400, Body: http.NoBody}, nil
	}}
	client := newScriptedClient(ctx, rt, Config{})
	_, err := client.Dial(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "400")
}

func TestDialHonorsCallerDeadlineWhileConnecting(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rt := &scriptedRoundTripper{respond: func(_ int, req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	}}
	client := newScriptedClient(ctx, rt, Config{})
	dialCtx, dialCancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer dialCancel()
	_, err := client.Dial(dialCtx)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestSessionFailureSurfacesToReaders(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	transportErr := errors.New("stream reset")
	rt := &scriptedRoundTripper{respond: func(call int, req *http.Request) (*http.Response, error) {
		if call == 1 {
			return emptyOK()
		}
		return nil, transportErr
	}}
	client := newScriptedClient(ctx, rt, Config{})
	session, err := client.newSession()
	require.NoError(t, err)
	require.NoError(t, session.connect(ctx))
	session.startPolling()
	// Established sessions tolerate transient failures but not a dead server.
	_, err = session.Read(make([]byte, 1))
	require.ErrorIs(t, err, transportErr)
	require.GreaterOrEqual(t, int(rt.calls.Load()), maxConsecutiveRequestFailures+1)
	_, err = session.Write([]byte("packet"))
	require.ErrorIs(t, err, transportErr)
}

func TestEstablishedSessionSurvivesTransientFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rt := &scriptedRoundTripper{respond: func(call int, req *http.Request) (*http.Response, error) {
		if call == 2 {
			return nil, errors.New("transient")
		}
		return emptyOK()
	}}
	client := newScriptedClient(ctx, rt, Config{})
	session, err := client.newSession()
	require.NoError(t, err)
	require.NoError(t, session.connect(ctx))
	session.startPolling()
	defer session.Close()
	require.Eventually(t, func() bool { return rt.calls.Load() >= 4 }, 3*time.Second, time.Millisecond)
	require.NoError(t, session.ctx.Err(), "one failed poll must not close an established session")
}

func TestOversizedPacketIsSentAlone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rt := &scriptedRoundTripper{respond: func(int, *http.Request) (*http.Response, error) { return emptyOK() }}
	client := newScriptedClient(ctx, rt, Config{MaxRequestSize: 8})
	session, err := client.newSession()
	require.NoError(t, err)
	require.NoError(t, session.connect(ctx))
	session.startPolling()
	defer session.Close()
	packet := make([]byte, 64)
	_, err = session.Write(packet)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		for _, length := range rt.bodyLengths() {
			if length >= len(packet) {
				return true
			}
		}
		return false
	}, time.Second, time.Millisecond, "a packet above max-request-size must still be sent instead of deferred forever")
}

func TestClosedConnReleasesSessionAfterGrace(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	cfg := testConfig()
	server, err := Listen(ctx, ln, cfg)
	require.NoError(t, err)
	defer server.Close()
	go func() {
		for {
			conn, err := server.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = echo(conn)
			}()
		}
	}()
	client, err := NewClient(ctx, func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", server.Addr().String())
	}, cfg)
	require.NoError(t, err)
	defer client.Close()
	conn, err := client.Dial(ctx)
	require.NoError(t, err)
	raw := conn.(*clientConn).raw
	require.NoError(t, conn.Close())
	require.Eventually(t, func() bool { return raw.ctx.Err() != nil }, sessionCloseGrace+2*time.Second, 10*time.Millisecond,
		"closing the conn must stop the session polling")
}

// The real server buffers headers until it has KCP data or the poll expires.
func TestDialDoesNotWaitForLongPollHeaders(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	cfg := testConfig()
	cfg.MaxWriteDurationMs = 5000
	server, err := Listen(ctx, ln, cfg)
	require.NoError(t, err)
	defer server.Close()
	go func() {
		conn, err := server.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = echo(conn)
	}()
	client, err := NewClient(ctx, func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Addr().String())
	}, cfg)
	require.NoError(t, err)
	defer client.Close()
	dialCtx, end := context.WithTimeout(ctx, time.Second)
	defer end()
	conn, err := client.Dial(dialCtx)
	require.NoError(t, err, "the first poll must not wait for data KCP cannot send yet")
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(2*time.Second)))
	_, err = conn.Write([]byte("probe"))
	require.NoError(t, err)
	got := make([]byte, 5)
	_, err = io.ReadFull(conn, got)
	require.NoError(t, err)
	require.Equal(t, "probe", string(got))
}

func TestRejectionAfterRequestWriteClosesReturnedConn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reject := make(chan struct{})
	rt := &scriptedRoundTripper{respond: func(_ int, req *http.Request) (*http.Response, error) {
		httptrace.ContextClientTrace(req.Context()).WroteRequest(httptrace.WroteRequestInfo{})
		select {
		case <-reject:
			return &http.Response{StatusCode: 403, Body: http.NoBody}, nil
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}}
	client := newScriptedClient(ctx, rt, Config{})
	conn, err := client.Dial(ctx)
	require.NoError(t, err)
	defer conn.Close()
	close(reject)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(time.Second)))
	_, err = conn.Read(make([]byte, 1))
	require.Error(t, err)
	require.NotErrorIs(t, err, context.DeadlineExceeded)
	require.ErrorContains(t, conn.(*clientConn).raw.closeErr(), "403")
}
