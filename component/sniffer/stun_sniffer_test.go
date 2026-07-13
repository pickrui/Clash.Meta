package sniffer

import (
	"encoding/binary"
	"testing"
)

func stunPacket(messageLength int, packetLength int) []byte {
	packet := make([]byte, packetLength)
	binary.BigEndian.PutUint16(packet[0:2], 0x0001)
	binary.BigEndian.PutUint16(packet[2:4], uint16(messageLength))
	binary.BigEndian.PutUint32(packet[4:8], stunMagicCookie)
	return packet
}

func TestDetectSTUNValidPacket(t *testing.T) {
	if err := detectSTUN(stunPacket(4, stunHeaderSize+4)); err != nil {
		t.Fatal(err)
	}
}

func TestDetectSTUNRejectsLengthMismatch(t *testing.T) {
	for _, packet := range [][]byte{
		stunPacket(4, stunHeaderSize),
		stunPacket(0, stunHeaderSize+4),
		stunPacket(2, stunHeaderSize+2),
	} {
		if err := detectSTUN(packet); err == nil {
			t.Fatal("detectSTUN accepted a malformed packet")
		}
	}
}
