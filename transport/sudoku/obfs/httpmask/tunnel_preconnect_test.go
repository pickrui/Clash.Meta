package httpmask

import (
	"context"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSessionPreconnectCount(t *testing.T) {
	if got := sessionPreconnectCount(); got != 3 {
		t.Fatalf("sessionPreconnectCount() = %d, want 3", got)
	}
}

func TestDialSessionPreconnectsUploadAndPull(t *testing.T) {
	var dialer *preconnectDialer
	server := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {
		if !waitForPreparedConns(dialer, tunnelPreconnectCount-1, 2*time.Second) {
			stdhttp.Error(w, "session preconnections not ready", stdhttp.StatusGatewayTimeout)
			return
		}
		_, _ = io.WriteString(w, "token=preconnected\ncap=upload-seq\n")
	}))
	defer server.Close()

	serverAddress := strings.TrimPrefix(server.URL, "http://")
	opts := TunnelDialOptions{
		Mode: string(TunnelModeStream),
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
	client, target, err := newHTTPClient(serverAddress, opts.TLSEnabled, opts.HostOverride, opts.DialContext, 4)
	if err != nil {
		t.Fatalf("new HTTP client: %v", err)
	}
	dialer = client.transport.dialer
	defer client.transport.close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := dialSessionWithClient(ctx, client.client, dialer, target, TunnelModeStream, opts, sessionPreconnectCount()); err != nil {
		t.Fatalf("dial session: %v", err)
	}
	if !waitForPreparedConns(dialer, tunnelPreconnectCount-1, time.Second) {
		t.Fatal("upload and pull preconnections was not retained")
	}
}

func waitForPreparedConns(dialer *preconnectDialer, count int, timeout time.Duration) bool {
	if dialer == nil || dialer.pool == nil {
		return false
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		dialer.pool.mu.Lock()
		ready := len(dialer.pool.ready)
		dialer.pool.mu.Unlock()
		if ready >= count {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return false
}
