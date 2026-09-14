package mekya

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/stretchr/testify/require"
)

type blockedRoundTripper struct {
	calls   atomic.Int32
	active  atomic.Int32
	body    bool
	release chan struct{}
}

func (r *blockedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	r.calls.Add(1)
	r.active.Add(1)
	if r.body {
		return &http.Response{StatusCode: 200, Body: &blockedResponseBody{ctx: req.Context(), active: &r.active, release: r.release}}, nil
	}
	defer r.active.Add(-1)
	select {
	case <-req.Context().Done():
	case <-r.release:
	}
	return nil, io.EOF
}

type blockedResponseBody struct {
	ctx     context.Context
	active  *atomic.Int32
	release chan struct{}
}

func (b *blockedResponseBody) Read([]byte) (int, error) {
	select {
	case <-b.ctx.Done():
	case <-b.release:
	}
	return 0, io.EOF
}
func (b *blockedResponseBody) Close() error { b.active.Add(-1); return nil }

func TestSessionBackpressure(t *testing.T) {
	for _, body := range []bool{false, true} {
		name := "headers"
		if body {
			name = "body"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			rt := &blockedRoundTripper{body: body, release: make(chan struct{}, 1)}
			client := &Client{ctx: ctx, cfg: Config{PollingIntervalInitial: 1}, url: "https://fixture.invalid/", rt: rt}
			session, err := client.newSession()
			require.NoError(t, err)
			defer session.Close()
			require.Eventually(t, func() bool { return rt.calls.Load() >= 32 }, 3*time.Second, time.Millisecond)
			require.Never(t, func() bool { return rt.calls.Load() > 32 }, 100*time.Millisecond, time.Millisecond,
				"a stalled transport must not accumulate unbounded requests")
			rt.release <- struct{}{}
			require.Eventually(t, func() bool { return rt.calls.Load() >= 33 }, 3*time.Second, time.Millisecond,
				"completion must allow queued polling to resume")
			require.NoError(t, session.Close())
			require.Eventually(t, func() bool { return rt.active.Load() == 0 }, 3*time.Second, time.Millisecond,
				"closing the session must release both requests and backpressure waits")
		})
	}
}
