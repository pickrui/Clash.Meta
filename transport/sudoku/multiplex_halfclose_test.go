package sudoku

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	sudokuobfs "github.com/metacubex/mihomo/transport/sudoku/obfs/sudoku"
)

func TestMultiplexHalfCloseThroughHandshake(t *testing.T) {
	for _, method := range []string{"aes-128-gcm", "chacha20-poly1305", "none"} {
		for _, pure := range []bool{false, true} {
			for _, padding := range []int{0, 100} {
				t.Run(fmt.Sprintf("%s/pure=%v/padding=%d", method, pure, padding), func(t *testing.T) {
					cfg := DefaultConfig()
					cfg.Key = "local-mux-half-close-test"
					cfg.Table = sudokuobfs.NewTable("local-half-close-table", "prefer_ascii")
					cfg.AEADMethod = method
					cfg.EnablePureDownlink = pure
					cfg.PaddingMin, cfg.PaddingMax = padding, padding
					cfg.DisableHTTPMask = true
					listener, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = listener.Close() })
					request := bytes.Repeat([]byte("request"), 40000) // spans multiple mux DATA frames
					response := bytes.Repeat([]byte("response"), 4000)
					const target = "logical-target.test:443"
					done := make(chan error, 1)
					finish := make(chan struct{})
					defer close(finish)
					go func() {
						done <- func() error {
							raw, err := listener.Accept()
							if err != nil {
								return err
							}
							defer raw.Close()
							conn, meta, err := ServerHandshake(raw, cfg)
							if err != nil {
								return err
							}
							_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
							session, err := ReadServerSession(conn, meta)
							if err != nil {
								return err
							}
							if session.Type != SessionTypeMultiplex {
								return fmt.Errorf("session type=%v", session.Type)
							}
							mux, err := AcceptMultiplexServer(conn)
							if err != nil {
								return err
							}
							defer mux.Close()
							for range 3 {
								stream, address, err := mux.AcceptTCP()
								if err != nil {
									return err
								}
								if address != target {
									return fmt.Errorf("unexpected target %s", address)
								}
								payload, err := io.ReadAll(stream)
								if err != nil {
									return err
								}
								if !bytes.Equal(payload, request) {
									return fmt.Errorf("request length=%d", len(payload))
								}
								if _, err := stream.Write(response); err != nil {
									return err
								}
								if err := stream.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
									return err
								}
								_ = stream.Close()
							}
							// Keep the shared tunnel alive until the client has consumed the
							// final response; half-close only terminates a logical direction.
							<-finish
							return nil
						}()
					}()
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = raw.Close() })
					_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
					conn, err := ClientHandshake(raw, cfg)
					if err != nil {
						t.Fatal(err)
					}
					mux, err := StartMultiplexClient(conn)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = mux.Close() })
					for range 3 {
						stream, err := mux.Dial(ctx, target)
						if err != nil {
							t.Fatal(err)
						}
						if n, err := stream.Write(request); err != nil || n != len(request) {
							t.Fatalf("request n=%d err=%v", n, err)
						}
						if err := stream.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
							t.Fatal(err)
						}
						got, err := io.ReadAll(stream)
						if err != nil || !bytes.Equal(got, response) {
							t.Fatalf("response length=%d err=%v", len(got), err)
						}
						_ = stream.Close()
					}
					// Signal completion without closing the channel twice in cleanup.
					finish <- struct{}{}
					select {
					case err := <-done:
						if err != nil {
							t.Fatal(err)
						}
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}
				})
			}
		}
	}
}
