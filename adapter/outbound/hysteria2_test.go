package outbound

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/structure"
	C "github.com/metacubex/mihomo/constant"
)

func TestHysteria2HandshakeTimeoutConfiguration(t *testing.T) {
	for _, seconds := range []int{0, 1} {
		t.Run(strconv.Itoa(seconds), func(t *testing.T) {
			peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			option := Hysteria2Option{}
			input := map[string]any{"name": "loopback", "server": "127.0.0.1", "port": peer.LocalAddr().(*net.UDPAddr).Port, "handshake-timeout": seconds}
			decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
			if err := decoder.Decode(input, &option); err != nil {
				t.Fatal(err)
			}
			client, err := NewHysteria2(option)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			metadata := &C.Metadata{Host: "example.test", DstPort: 443}
			go func() {
				conn, err := client.DialContext(ctx, metadata)
				if conn != nil {
					_ = conn.Close()
				}
				result <- err
			}()
			_ = peer.SetReadDeadline(time.Now().Add(3 * time.Second))
			if _, _, err := peer.ReadFrom(make([]byte, 2048)); err != nil {
				t.Fatal(err)
			}
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancelled request: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("request cancellation did not return")
			}
			if seconds > 0 {
				// The second request must join the original offer and see its one-second
				// deadline, not wait for this request's five-second deadline.
				next, cancelNext := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancelNext()
				_, err := client.DialContext(next, metadata)
				if !errors.Is(err, context.DeadlineExceeded) || next.Err() != nil {
					t.Fatalf("configured handshake timeout was not applied: %v (caller: %v)", err, next.Err())
				}
			}
		})
	}
}
