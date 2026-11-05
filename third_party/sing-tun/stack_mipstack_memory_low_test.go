//go:build with_mips_low_memory

package tun

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mipstack"
	M "github.com/metacubex/sing/common/metadata"
)

func TestMipsLowMemoryTUNStream(t *testing.T) {
	for _, pair := range [][2]string{{"198.18.0.1", "192.0.2.2"}, {"fd00::1", "2001:db8::2"}} {
		t.Run(pair[0], func(t *testing.T) {
			source, destination := netip.MustParseAddr(pair[0]), netip.MustParseAddr(pair[1])
			device := newMemoryTun()
			result := make(chan error, 1)
			handler := &testHandler{tcp: func(_ context.Context, conn net.Conn, _ M.Metadata) error {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
				info := conn.(*mipstack.TCPConn).Info()
				if info.ReceiveBufferCapacity != 32<<10 || info.SendBufferCapacity != 32<<10 ||
					info.MaximumReceiveBuffer != 128<<10 || info.MaximumSendBuffer != 128<<10 {
					result <- fmt.Errorf("unexpected accepted TCP buffer profile: %+v", info)
					return nil
				}
				_, err := io.Copy(conn, conn)
				result <- err
				return err
			}}
			server := testStack(t, device, handler, nil)
			client, err := mipstack.New(mipstack.Config{
				LocalAddresses: []netip.Prefix{netip.PrefixFrom(source, source.BitLen())},
				MTU:            1500,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			if err := client.Start(); err != nil {
				t.Fatal(err)
			}
			var pumps sync.WaitGroup
			pumps.Add(2)
			go func() {
				defer pumps.Done()
				buffers, sizes := [][]byte{make([]byte, 1500)}, make([]int, 1)
				for {
					if _, err := client.Read(buffers, sizes, 0); err != nil {
						return
					}
					select {
					case device.in <- bytes.Clone(buffers[0][:sizes[0]]):
					case <-device.done:
						return
					}
				}
			}()
			go func() {
				defer pumps.Done()
				for {
					select {
					case packet := <-device.out:
						if _, err := client.Write([][]byte{packet}, 0); err != nil {
							return
						}
					case <-device.done:
						return
					}
				}
			}()
			t.Cleanup(func() {
				_ = client.Close()
				_ = device.Close()
				_ = server.Close()
				pumps.Wait()
			})
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			network := "tcp4"
			if source.Is6() {
				network = "tcp6"
			}
			conn, err := client.DialTCP(ctx, network, netip.AddrPort{}, netip.AddrPortFrom(destination, 443))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
			for _, size := range []int{1, 1200, 32 << 10, 1 << 20, 1200} {
				payload := bytes.Repeat([]byte{0x59}, size)
				written := make(chan error, 1)
				go func() { _, err := conn.Write(payload); written <- err }()
				received := make([]byte, size)
				if _, err := io.ReadFull(conn, received); err != nil {
					t.Fatal(err)
				}
				if err := <-written; err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(received, payload) {
					t.Fatalf("%d-byte transfer corrupted", size)
				}
			}
			if err := conn.(*mipstack.TCPConn).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-result:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		})
	}
}
