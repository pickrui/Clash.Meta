//go:build linux

package tun

import (
	"context"
	"encoding/binary"
	"net/netip"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMipsLinuxGROMergesOutput(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "tun-output")
	require.NoError(t, err)
	defer file.Close()
	device := &NativeTun{tunFile: file, vnetHdr: true, tcpGROTable: newTCPGROTable(), udpGROTable: newUDPGROTable()}
	s := &Mipstack{ctx: context.Background(), tun: device}
	source, target := netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("198.18.0.2")
	first := tcpPacket(source, target, 100, 200, 16, []byte("abcd"))
	second := tcpPacket(source, target, 104, 200, 16, []byte("efgh"))
	require.NoError(t, s.writePackets([][]byte{first, second}, 0))
	data, err := os.ReadFile(file.Name())
	require.NoError(t, err)
	// A single virtio/IP/TCP header followed by both payloads proves that the
	// batch survived the wrapper and had enough writable tailroom for GRO.
	require.Len(t, data, virtioNetHdrLen+40+8)
	require.Equal(t, "abcdefgh", string(data[virtioNetHdrLen+40:]))
}

func TestUDPZeroChecksumNeverCoalesces(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		source, target, offset := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), 20
		if v6 {
			source, target, offset = netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2"), 40
		}
		for _, skip := range []bool{false, true} {
			for zero := -1; zero <= 1; zero++ {
				first := udpPacket(source, target, 53, []byte("first"))
				second := udpPacket(source, target, 53, []byte("later"))
				head := make([]byte, len(first), len(first)+len(second))
				copy(head, first)
				want := coalesceSuccess
				if zero == 0 {
					binary.BigEndian.PutUint16(head[offset+6:], 0)
					want = coalesceItemInvalidCSum
				}
				if zero == 1 {
					binary.BigEndian.PutUint16(second[offset+6:], 0)
					want = coalescePktInvalidCSum
				}
				item := udpGROItem{iphLen: uint8(offset), gsoSize: 5}
				got := coalesceUDPPackets(second, &item, [][]byte{head}, 0, v6, skip)
				if got != want {
					t.Fatalf("v6=%v skip=%v zero=%d: got %v want %v", v6, skip, zero, got, want)
				}
			}
		}
	}
}
