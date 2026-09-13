package trojan

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/metacubex/mihomo/transport/socks5"
)

type failingPacketWriter struct {
	calls     int
	failAfter int
	failure   error
}

func (w *failingPacketWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls > w.failAfter {
		return 3, w.failure
	}
	return len(p), nil
}

func TestWritePacketReportsPayloadLength(t *testing.T) {
	addr := socks5.ParseAddr("192.0.2.1:5353")
	for _, size := range []int{0, 7, maxLength, maxLength + 17} {
		payload := bytes.Repeat([]byte{'a'}, size)
		wire := new(bytes.Buffer)
		n, err := WritePacket(wire, addr, payload)
		if err != nil || n != len(payload) {
			t.Errorf("size=%d returned=%d err=%v", size, n, err)
		}
		var decoded []byte
		for wire.Len() > 0 {
			packet := make([]byte, maxLength)
			remote, n, remain, err := ReadPacket(wire, packet)
			if err != nil || remain != 0 || remote.String() != "192.0.2.1:5353" {
				t.Fatalf("decode: %v %d %v", remote, remain, err)
			}
			decoded = append(decoded, packet[:n]...)
		}
		if !bytes.Equal(decoded, payload) {
			t.Fatal("wire payload changed")
		}
	}
}

func TestWritePacketCountsOnlyCompletedPayloadOnFailure(t *testing.T) {
	for _, completed := range []int{0, 1} {
		failure := io.ErrClosedPipe
		writer := &failingPacketWriter{failAfter: completed, failure: failure}
		n, err := WritePacket(writer, socks5.ParseAddr("192.0.2.1:5353"), make([]byte, maxLength+17))
		if !errors.Is(err, failure) || n != completed*maxLength {
			t.Fatalf("completed=%d returned=%d err=%v", completed, n, err)
		}
	}
}
