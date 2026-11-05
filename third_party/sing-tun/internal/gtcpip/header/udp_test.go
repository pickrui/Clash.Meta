package header

import (
	"testing"

	tcpip "github.com/metacubex/sing-tun/internal/gtcpip"
)

func TestUDPZeroChecksum(t *testing.T) {
	src := tcpip.AddrFrom4([4]byte{192, 0, 2, 1})
	dst := tcpip.AddrFrom4([4]byte{192, 0, 2, 2})
	h := UDP(make([]byte, UDPMinimumSize))
	h.Encode(&UDPFields{SrcPort: 1000, DstPort: 2000, Length: UDPMinimumSize})
	h.SetSourcePortWithChecksumUpdate(3000)
	h.SetDestinationPortWithChecksumUpdate(4000)
	h.UpdateChecksumPseudoHeaderAddress(src, dst, true)
	if h.Checksum() != 0 || h.SourcePort() != 3000 || h.DestinationPort() != 4000 {
		t.Fatalf("rewriting disabled checksum: %x", []byte(h))
	}
	for _, skip := range []bool{false, true} {
		for _, proto := range []tcpip.NetworkProtocolNumber{IPv4ProtocolNumber, IPv6ProtocolNumber} {
			length, valid := UDPValid(h, func() uint16 { t.Fatal("zero checksum must not read payload"); return 0 }, 0, proto, src, dst, skip)
			if !length || valid != (proto == IPv4ProtocolNumber) {
				t.Fatalf("proto=%d skip=%v length=%v valid=%v", proto, skip, length, valid)
			}
		}
	}
	h.SetChecksum(0xffff)
	h.SetSourcePortWithChecksumUpdate(3000)
	if h.Checksum() != 0xffff {
		t.Fatal("computed zero checksum lost its enabled marker")
	}
	h.SetChecksum(0)
	h.UpdateChecksumPseudoHeaderAddress(src, dst, false)
	if h.Checksum() == 0 {
		t.Fatal("partial offload checksum was not updated")
	}
}
