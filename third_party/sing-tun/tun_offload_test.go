package tun

import (
	"encoding/binary"
	"testing"
)

func TestGSOComputedZeroUDPChecksum(t *testing.T) {
	for _, partial := range []bool{false, true} {
		packet := make([]byte, 8)
		binary.BigEndian.PutUint16(packet, 0xffff)
		out := [][]byte{make([]byte, 8)}
		n, err := GSOSplit(packet, GSOOptions{CsumOffset: 6, NeedsCsum: partial}, out, make([]int, 1), 0)
		if err != nil || n != 1 {
			t.Fatalf("split: %d, %v", n, err)
		}
		want := uint16(0)
		if partial {
			want = 0xffff
		}
		if got := binary.BigEndian.Uint16(out[0][6:]); got != want {
			t.Fatalf("partial=%v checksum=%x want=%x", partial, got, want)
		}
	}
}
