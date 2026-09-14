package sudoku

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// A proxy can lose a successful authorization response after the server has
// consumed its nonce. Both an HTTP retry and stream-to-poll fallback must use a
// new handshake, without weakening the server's replay protection.
func TestHTTPMaskTunnelEarlyHandshakeRetries(t *testing.T) {
	for _, mode := range []string{"poll", "auto"} {
		t.Run(mode, func(t *testing.T) {
			cfg := newTunnelTestTable(t, "early-retry-"+mode)
			cfg.HTTPMaskMode = mode
			codec := newHTTPMaskEarlyCodecConfig(cfg, ServerAEADSeed(cfg.Key))
			var mu sync.Mutex
			seen := make(map[[kipHelloNonceSize]byte]bool)
			attempts, replays := 0, 0
			var downlink []byte
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/session":
					mu.Lock()
					defer mu.Unlock()
					attempts++
					payload, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("ed"))
					if err != nil {
						t.Errorf("decode early payload: %v", err)
						http.Error(w, "bad request", http.StatusBadRequest)
						return
					}
					state, err := ProcessEarlyClientPayload(codec, cfg.tableCandidates(), payload,
						func(_ string, nonce [kipHelloNonceSize]byte, _ time.Time) bool {
							if seen[nonce] {
								replays++
								return false
							}
							seen[nonce] = true
							return true
						})
					if err != nil {
						http.Error(w, "not found", http.StatusNotFound)
						return
					}
					// The first poll response, or all stream responses, are lost
					// at the proxy after the real protocol handshake is accepted.
					if attempts == 1 || r.Header.Get("X-Sudoku-Tunnel") == "stream" {
						http.Error(w, "upstream response lost", http.StatusBadGateway)
						return
					}
					memory := newEarlyMemoryConn(nil)
					conn, err := state.WrapConn(memory)
					if err == nil {
						_, err = conn.Write([]byte("ok"))
					}
					if err != nil {
						t.Errorf("encode downlink: %v", err)
						http.Error(w, "encode failed", http.StatusInternalServerError)
						return
					}
					downlink = memory.Written()
					_ = conn.Close()
					fmt.Fprintf(w, "token=retrySession\ned=%s\n", base64.RawURLEncoding.EncodeToString(state.ResponsePayload))
				case "/stream":
					mu.Lock()
					payload := append([]byte(nil), downlink...)
					mu.Unlock()
					fmt.Fprintln(w, base64.StdEncoding.EncodeToString(payload))
					w.(http.Flusher).Flush()
					<-r.Context().Done()
				default:
					w.WriteHeader(http.StatusOK)
				}
			}))
			defer server.Close()
			cfg.ServerAddress = strings.TrimPrefix(server.URL, "http://")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			conn, err := DialHTTPMaskTunnel(ctx, cfg.ServerAddress, cfg, (&net.Dialer{}).DialContext,
				func(net.Conn) (net.Conn, error) {
					return nil, errors.New("accepted early handshake unexpectedly used legacy upgrade")
				})
			if err != nil {
				t.Fatalf("dial after lost authorization response: %v", err)
			}
			defer conn.Close()
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			got := make([]byte, 2)
			if _, err := io.ReadFull(conn, got); err != nil || string(got) != "ok" {
				t.Fatalf("read with accepted attempt's session keys: %q, %v", got, err)
			}
			mu.Lock()
			defer mu.Unlock()
			wantAttempts := 2
			if mode == "auto" {
				wantAttempts = 4
			}
			if attempts != wantAttempts || len(seen) != wantAttempts || replays != 0 {
				t.Fatalf("attempts=%d, unique nonces=%d, replays=%d; want %d independent handshakes", attempts, len(seen), replays, wantAttempts)
			}
		})
	}
}
