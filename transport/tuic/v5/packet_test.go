package v5

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"

	N "github.com/metacubex/mihomo/common/net"
)

type packetTestInput struct {
	net.Conn
	reader io.Reader
}

func (c *packetTestInput) Read(p []byte) (int, error) { return c.reader.Read(p) }

func TestPacketReadFromReassemblesFragments(t *testing.T) {
	chunks := [][]byte{[]byte("first-"), []byte("middle-"), []byte("last")}
	full := bytes.Join(chunks, nil)
	destination := netip.MustParseAddrPort("192.0.2.1:5353")
	for _, order := range [][]int{{0, 1, 2}, {2, 0, 1}, {0, 0, 2, 1}} {
		for _, size := range []int{4, 64} {
			t.Run(fmt.Sprintf("order=%v/buffer=%d", order, size), func(t *testing.T) {
				wire := new(bytes.Buffer)
				for _, id := range order {
					address := Address{TYPE: AtypNone}
					if id == 0 {
						address = NewAddressAddrPort(destination)
					}
					packet := NewPacket(1, 2, 3, uint8(id), uint16(len(chunks[id])), address, chunks[id])
					if err := packet.WriteTo(wire); err != nil {
						t.Fatal(err)
					}
				}
				next := NewPacket(1, 3, 1, 0, 4, NewAddressAddrPort(destination), []byte("next"))
				if err := next.WriteTo(wire); err != nil {
					t.Fatal(err)
				}
				conn := &quicStreamPacketConn{inputConn: N.NewBufferedConn(&packetTestInput{reader: wire})}
				payload := make([]byte, size)
				n, addr, err := conn.ReadFrom(payload)
				if err != nil {
					t.Fatal(err)
				}
				want := full[:min(len(full), size)]
				if !bytes.Equal(payload[:n], want) || addr.String() != destination.String() {
					t.Fatalf("got %q from %v, want %q", payload[:n], addr, want)
				}
				n, _, err = conn.ReadFrom(payload)
				if err != nil || string(payload[:n]) != "next" {
					t.Fatalf("next datagram: %q, %v", payload[:n], err)
				}
			})
		}
	}
}
