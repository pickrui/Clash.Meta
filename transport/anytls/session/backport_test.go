package session

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type captureFrameConn struct {
	net.Conn
	mu   sync.Mutex
	data bytes.Buffer
}

func (c *captureFrameConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.data.Write(p)
}
func (c *captureFrameConn) Close() error                     { return nil }
func (c *captureFrameConn) SetDeadline(time.Time) error      { return nil }
func (c *captureFrameConn) SetWriteDeadline(time.Time) error { return nil }

func TestAnyTLSLargeDataFrames(t *testing.T) {
	for _, size := range []int{0, 65535, 65536, 131081} {
		t.Run(stringSize(size), func(t *testing.T) {
			raw := &captureFrameConn{}
			s := NewServerSession(raw, nil, nil)
			data := bytes.Repeat([]byte{0x41}, size)
			n, err := s.writeDataFrame(7, data)
			if err != nil || n != size {
				t.Fatalf("write: %d %v", n, err)
			}
			var decoded []byte
			frames := 0
			for raw.data.Len() > 0 {
				var hdr rawHeader
				if _, err := io.ReadFull(&raw.data, hdr[:]); err != nil {
					t.Fatal(err)
				}
				if hdr.Cmd() != cmdPSH || hdr.StreamID() != 7 || hdr.Length() == 0 {
					t.Fatalf("invalid frame after %d payload bytes: %v", len(decoded), hdr)
				}
				chunk := make([]byte, hdr.Length())
				if _, err := io.ReadFull(&raw.data, chunk); err != nil {
					t.Fatal(err)
				}
				decoded = append(decoded, chunk...)
				frames++
			}
			if !bytes.Equal(data, decoded) || frames != (size+65534)/65535 {
				t.Fatal("large write was truncated or misframed")
			}
		})
	}
}

func stringSize(n int) string {
	if n == 0 {
		return "empty"
	}
	if n == 65535 {
		return "maximum"
	}
	if n == 65536 {
		return "overflow"
	}
	return "multiple_frames"
}

func TestAnyTLSLargeWritesRemainContiguous(t *testing.T) {
	raw := &captureFrameConn{}
	s := NewServerSession(raw, nil, nil)
	var wg sync.WaitGroup
	for _, sid := range []uint32{1, 2} {
		wg.Go(func() {
			_, err := s.writeDataFrame(sid, bytes.Repeat([]byte{byte(sid)}, 131081))
			if err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	groups := 0
	var previous uint32
	totals := map[uint32]int{}
	for raw.data.Len() > 0 {
		var h rawHeader
		if _, err := io.ReadFull(&raw.data, h[:]); err != nil {
			t.Fatal(err)
		}
		sid := binary.BigEndian.Uint32(h[1:5])
		if sid != 1 && sid != 2 {
			t.Fatal("bad stream ID")
		}
		if sid != previous {
			previous = sid
			groups++
		}
		data := make([]byte, h.Length())
		if _, err := io.ReadFull(&raw.data, data); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, bytes.Repeat([]byte{byte(sid)}, len(data))) {
			t.Fatal("payload corruption")
		}
		totals[sid] += len(data)
	}
	if groups != 2 || totals[1] != 131081 || totals[2] != 131081 {
		t.Fatal("concurrent writes interleaved their frame sequences")
	}
}
