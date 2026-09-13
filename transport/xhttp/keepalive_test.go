package xhttp

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

type keepaliveResponseWriter struct {
	header http.Header
	status chan int
	writes chan []byte
}

func (w *keepaliveResponseWriter) Header() http.Header    { return w.header }
func (w *keepaliveResponseWriter) WriteHeader(status int) { w.status <- status }
func (w *keepaliveResponseWriter) Write(p []byte) (int, error) {
	select {
	case w.writes <- bytes.Clone(p):
	default:
	}
	return 0, io.ErrClosedPipe // Stop the padding loop after observing its first write.
}
func (w *keepaliveResponseWriter) Flush() {}

func TestStreamUpKeepaliveWithObfuscatedPadding(t *testing.T) {
	for _, tc := range []struct {
		name, placement         string
		obfs, disabled, invalid bool
	}{
		{name: "legacy"},
		{name: "header", placement: PlacementHeader, obfs: true},
		{name: "cookie", placement: PlacementCookie, obfs: true},
		{name: "query", placement: PlacementQuery, obfs: true},
		{name: "disabled", placement: PlacementHeader, obfs: true, disabled: true},
		{name: "invalid", placement: PlacementHeader, obfs: true, invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := Config{Path: "/xhttp", Mode: "stream-up", XPaddingBytes: "8", XPaddingObfsMode: tc.obfs, XPaddingPlacement: tc.placement, XPaddingHeader: "X-Test-Padding", XPaddingKey: "padding", ScStreamUpServerSecs: "1"}
			if tc.disabled {
				config.ScStreamUpServerSecs = "0"
			}
			handler, err := NewServerHandler(ServerOption{Config: config})
			if err != nil {
				t.Fatal(err)
			}
			h := handler.(*requestHandler)
			session := h.upsertSession("session")
			session.markConnected() // End the orphan-session reaper for this isolated upload.
			t.Cleanup(func() { h.deleteSession("session") })
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			req := httptest.NewRequest(http.MethodPost, "https://example.com/xhttp/", http.NoBody).WithContext(ctx)
			if err := config.FillStreamRequest(req, "session"); err != nil {
				t.Fatal(err)
			}
			if tc.obfs && req.Header.Get("Referer") != "" {
				t.Fatal("test accidentally uses the legacy marker")
			}
			if tc.invalid {
				req.Header.Del("X-Test-Padding")
			}
			writer := &keepaliveResponseWriter{header: make(http.Header), status: make(chan int, 1), writes: make(chan []byte, 1)}
			done := make(chan struct{})
			go func() { defer close(done); handler.ServeHTTP(writer, req) }()
			t.Cleanup(func() {
				cancel()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Error("upload handler did not stop")
				}
			})
			select {
			case status := <-writer.status:
				want := http.StatusOK
				if tc.invalid {
					want = http.StatusBadRequest
				}
				if status != want {
					t.Fatalf("status=%d, want %d", status, want)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("no upload response")
			}
			if tc.invalid {
				return
			}
			if tc.disabled {
				select {
				case data := <-writer.writes:
					t.Fatalf("disabled keepalive wrote %q", data)
				case <-time.After(100 * time.Millisecond):
				}
			} else {
				select {
				case data := <-writer.writes:
					if string(data) != "XXXXXXXX" {
						t.Errorf("padding=%q", data)
					}
				case <-time.After(time.Second):
					t.Fatal("missing stream-up keepalive")
				}
			}
		})
	}
}
