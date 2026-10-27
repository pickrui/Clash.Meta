//go:build !linux

package tproxy

import (
	"io"
	"net"
	"testing"
)

func TestUnsupportedPlatformReleasesSocket(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			var probe io.Closer
			var address string
			if network == "tcp" {
				listener, err := net.Listen(network, "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				address, probe = listener.Addr().String(), listener
			} else {
				socket, err := net.ListenPacket(network, "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				address, probe = socket.LocalAddr().String(), socket
			}
			probe.Close()
			if network == "tcp" {
				if listener, err := New(address, nil); err == nil {
					listener.Close()
					t.Fatal("unsupported TProxy initialization succeeded")
				}
				listener, err := net.Listen(network, address)
				if err != nil {
					t.Fatalf("failed TProxy initialization retained TCP socket: %v", err)
				}
				listener.Close()
			} else {
				if socket, err := NewUDP(address, nil); err == nil {
					socket.Close()
					t.Fatal("unsupported TProxy initialization succeeded")
				}
				socket, err := net.ListenPacket(network, address)
				if err != nil {
					t.Fatalf("failed TProxy initialization retained UDP socket: %v", err)
				}
				socket.Close()
			}
		})
	}
}
