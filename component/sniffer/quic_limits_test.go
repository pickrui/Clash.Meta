package sniffer

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/metacubex/quic-go/quicvarint"
)

func TestQUICLargeInitialPacketScratchSpace(t *testing.T) {
	for _, padding := range []int{16 * 1024, 32 * 1024} {
		t.Run(fmt.Sprint(padding), func(t *testing.T) {
			defer func() {
				if err := recover(); err != nil {
					t.Errorf("large valid Initial panicked: %v", err)
				}
			}()
			hello := makeTestClientHello("large.test", 0)
			frames := quicvarint.Append([]byte{frameCrypto}, 0)
			frames = quicvarint.Append(frames, uint64(len(hello)))
			frames = append(frames, hello...)
			frames = append(frames, make([]byte, padding)...)
			dcid := []byte("large initial")
			wire, _ := makeProtectedQUICInitialPacket(t, dcid, expandLabels(dcid, &quicV1), 0, 1, frames)
			original := bytes.Clone(wire)
			q := &quicPacketSender{done: make(chan struct{})}
			defer q.close()
			if err := q.readQUICData(wire); err != nil {
				t.Fatal(err)
			}
			if q.result != "large.test" {
				t.Fatalf("host=%q", q.result)
			}
			if !bytes.Equal(wire, original) {
				t.Fatal("QUIC packet changed during sniffing")
			}
		})
	}
}

func FuzzSnifferInputs(f *testing.F) {
	hello := makeTestClientHello("fuzz.test", 0)
	f.Add(uint8(0), makeTestTLSRecords(hello, 2, 40))
	f.Add(uint8(0), []byte{0x16, 3, 3, 0xff, 0xff})
	f.Add(uint8(1), []byte("GET / HTTP/1.1\r\nHost: fuzz.test\r\n\r\n"))
	f.Add(uint8(1), makeTestHTTP2Input(makeTestHTTP2Frame(h2FrameHeaders, h2FlagEndHeaders, 1, []byte{0x41, 9, 'f', 'u', 'z', 'z', '.', 't', 'e', 's', 't'})))
	frames := quicvarint.Append([]byte{frameCrypto}, 0)
	frames = quicvarint.Append(frames, uint64(len(hello)))
	frames = append(frames, hello...)
	f.Add(uint8(2), frames)
	f.Add(uint8(2), []byte{frameConnectionClose, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Add(uint8(3), frames)
	f.Add(uint8(3), make([]byte, 32*1024))
	f.Add(uint8(4), []byte{0xc0, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0})
	f.Fuzz(func(t *testing.T, protocol uint8, input []byte) {
		if len(input) > 64*1024 {
			t.Skip()
		}
		original := bytes.Clone(input)
		switch protocol % 5 {
		case 0:
			_, _ = SniffTLS(input)
		case 1:
			h, _ := NewHTTPSniffer(SnifferConfig{})
			_, _ = h.SniffData(input)
		default:
			q := &quicPacketSender{done: make(chan struct{})}
			defer q.close()
			switch protocol % 5 {
			case 2:
				_ = q.readQUICFrames(input)
			case 3:
				// Authenticate arbitrary frame bytes to exercise the complete Initial
				// decoder, rather than stopping at AEAD failures for every mutation.
				frames := append(bytes.Clone(input), 0, 0, 0)
				dcid := []byte("fuzz dcid")
				packet, _ := makeProtectedQUICInitialPacket(t, dcid, expandLabels(dcid, &quicV1), 0, 1, frames)
				before := bytes.Clone(packet)
				_ = q.readQUICData(packet)
				if !bytes.Equal(packet, before) {
					t.Fatal("Initial decoder modified packet")
				}
			case 4:
				_ = q.readQUICData(input)
			}
			if cap(q.buffer) > maxCryptoStreamOffset || len(q.receivedCryptoData.words)*8 > maxCryptoStreamOffset/8 || len(q.initialKeys) > 2 {
				t.Fatal("QUIC retained data exceeds its resource bounds")
			}
		}
		if !bytes.Equal(input, original) {
			t.Fatal("sniffer modified input")
		}
	})
}

func TestQUICInitialPacketBudget(t *testing.T) {
	dcid := []byte("oversized initial")
	wire, _ := makeProtectedQUICInitialPacket(t, dcid, expandLabels(dcid, &quicV1), 0, 1, make([]byte, maxInitialPacketSize))
	q := &quicPacketSender{done: make(chan struct{})}
	defer q.close()
	if err := q.readQUICData(wire); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("oversized packet = %v", err)
	}
	if q.buffer != nil || len(q.initialKeys) != 0 {
		t.Fatal("oversized packet allocated retained crypto state")
	}
}
