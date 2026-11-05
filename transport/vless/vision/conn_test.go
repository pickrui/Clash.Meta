package vision

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/transport/vless/encryption"
)

var testUUID = uuid.Must(uuid.FromString("d342d11e-d424-4583-b36e-524ab1f0afa4"))

type observedConn struct {
	net.Conn
	readStarted  chan struct{}
	writeStarted chan struct{}
	readOnce     sync.Once
	writeOnce    sync.Once
	closes       atomic.Int32
}

func (c *observedConn) Read(p []byte) (int, error) {
	c.readOnce.Do(func() {
		if c.readStarted != nil {
			close(c.readStarted)
		}
	})
	return c.Conn.Read(p)
}
func (c *observedConn) Write(p []byte) (int, error) {
	c.writeOnce.Do(func() {
		if c.writeStarted != nil {
			close(c.writeStarted)
		}
	})
	return c.Conn.Write(p)
}
func (c *observedConn) Close() error { c.closes.Add(1); return c.Conn.Close() }

func newTestConn(t *testing.T, outer, direct net.Conn) *Conn {
	t.Helper()
	c, err := NewConn(outer, &encryption.CommonConn{Conn: direct}, testUUID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { outer.Close(); direct.Close(); c.Close() })
	return c
}
func waitResult(t *testing.T, ch <-chan error) {
	t.Helper()
	select {
	case err := <-ch:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("I/O did not finish")
	}
}
func waitStarted(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("I/O did not start")
	}
}
func visionFrame(first bool, command byte, payload []byte) []byte {
	var out []byte
	if first {
		out = append(out, testUUID.Bytes()...)
	}
	header := []byte{command, 0, 0, 0, 3}
	binary.BigEndian.PutUint16(header[1:3], uint16(len(payload)))
	out = append(out, header...)
	out = append(out, payload...)
	return append(out, 0, 0, 0)
}
func readVisionFrame(r io.Reader, first bool) (byte, []byte, error) {
	if first {
		var id [16]byte
		if _, err := io.ReadFull(r, id[:]); err != nil {
			return 0, nil, err
		}
		if !bytes.Equal(id[:], testUUID.Bytes()) {
			return 0, nil, errors.New("bad UUID")
		}
	}
	var h [5]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	p := make([]byte, binary.BigEndian.Uint16(h[1:3]))
	if _, err := io.ReadFull(r, p); err != nil {
		return 0, nil, err
	}
	_, err := io.CopyN(io.Discard, r, int64(binary.BigEndian.Uint16(h[3:5])))
	return h[0], p, err
}
func observeState(c *Conn, stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	for {
		select {
		case <-stop:
			return
		default:
		}
		c.FrontHeadroom()
		c.RearHeadroom()
		c.NeedHandshake()
		c.Upstream()
		c.ReaderPossiblyReplaceable()
		c.ReaderReplaceable()
		c.WriterPossiblyReplaceable()
		c.WriterReplaceable()
		N.UnwrapReader(c)
		N.UnwrapWriter(c)
	}
}

func TestVisionFullDuplex(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	c := newTestConn(t, local, local)
	stop, observed := make(chan struct{}), make(chan struct{})
	go observeState(c, stop, observed)
	defer func() { close(stop); <-observed }()
	const count = 32
	payload := bytes.Repeat([]byte("payload"), 19)
	received := make(chan error, 1)
	go func() {
		for i := 0; i < count; i++ {
			p := make([]byte, len(payload))
			if _, err := io.ReadFull(c, p); err != nil {
				received <- err
				return
			}
			if !bytes.Equal(p, payload) {
				received <- errors.New("read payload changed")
				return
			}
		}
		received <- nil
	}()
	sent := make(chan error, 1)
	go func() {
		for i := 0; i < count; i++ {
			if _, err := c.Write(payload); err != nil {
				sent <- err
				return
			}
		}
		sent <- nil
	}()
	peerSent := make(chan error, 1)
	go func() {
		for i := 0; i < count; i++ {
			cmd := commandPaddingContinue
			if i == count-1 {
				cmd = commandPaddingEnd
			}
			frame := visionFrame(i == 0, cmd, payload)
			if i == count-1 {
				// The last Read returns the payload; no following Read drains padding.
				frame[3], frame[4] = 0, 0
				frame = frame[:len(frame)-3]
			}
			if _, err := peer.Write(frame); err != nil {
				peerSent <- err
				return
			}
		}
		peerSent <- nil
	}()
	peerReceived := make(chan error, 1)
	go func() {
		padded := true
		for i := 0; i < count; i++ {
			var data []byte
			var err error
			if padded {
				var cmd byte
				cmd, data, err = readVisionFrame(peer, i == 0)
				padded = cmd == commandPaddingContinue
			} else {
				data = make([]byte, len(payload))
				_, err = io.ReadFull(peer, data)
			}
			if err != nil {
				peerReceived <- err
				return
			}
			if !bytes.Equal(data, payload) {
				peerReceived <- errors.New("written payload changed")
				return
			}
		}
		peerReceived <- nil
	}()
	waitResult(t, sent)
	waitResult(t, received)
	waitResult(t, peerSent)
	waitResult(t, peerReceived)
	if c.NeedHandshake() {
		t.Fatal("UUID still pending after successful writes")
	}
}

func TestVisionCloseUnblocksBothDirections(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	outer := &observedConn{Conn: local, readStarted: make(chan struct{}), writeStarted: make(chan struct{})}
	c := newTestConn(t, outer, local)
	readDone, writeDone := make(chan error, 1), make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 16))
		if err == nil {
			err = errors.New("read succeeded after close")
		} else {
			err = nil
		}
		readDone <- err
	}()
	go func() {
		_, err := c.Write([]byte("blocked"))
		if err == nil {
			err = errors.New("write succeeded after close")
		} else {
			err = nil
		}
		writeDone <- err
	}()
	waitStarted(t, outer.readStarted)
	waitStarted(t, outer.writeStarted)
	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	waitResult(t, closed)
	waitResult(t, readDone)
	waitResult(t, writeDone)
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("late")); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}

func TestVisionDirectReadDrainsBuffers(t *testing.T) {
	outerLocal, outerPeer := net.Pipe()
	defer outerPeer.Close()
	directLocal, directPeer := net.Pipe()
	defer directPeer.Close()
	outer := &observedConn{Conn: outerLocal}
	direct := &observedConn{Conn: directLocal}
	c := newTestConn(t, outer, direct)
	c.input = bytes.NewReader([]byte("tls-queued"))
	c.rawInput = bytes.NewBufferString("raw-queued")
	sent := make(chan error, 1)
	go func() {
		_, err := outerPeer.Write(visionFrame(true, commandPaddingDirect, []byte("content")))
		sent <- err
	}()
	directSent := make(chan error, 1)
	go func() { _, err := directPeer.Write([]byte("socket")); directSent <- err }()
	var got []byte
	want := []byte("contenttls-queuedraw-queuedsocket")
	for len(got) < len(want) {
		var p [2]byte
		n, err := c.Read(p[:])
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, p[:n]...)
		if len(got) < len("contenttls-queuedraw-queued") && c.ReaderReplaceable() {
			t.Fatal("reader replaced before queued bytes were consumed")
		}
		if N.UnwrapWriter(c) != c {
			t.Fatal("read transition replaced the write direction")
		}
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("direct transition changed bytes: %q", got)
	}
	waitResult(t, sent)
	waitResult(t, directSent)
	if !c.ReaderReplaceable() || N.UnwrapReader(c) != direct {
		t.Fatal("reader did not switch to raw connection")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if direct.closes.Load() != 1 || outer.closes.Load() != 0 {
		t.Fatal("direct close used TLS wrapper")
	}
}

func TestVisionDirectWritePublishesAfterCommand(t *testing.T) {
	for _, closing := range []bool{false, true} {
		name := "complete"
		if closing {
			name = "close_during_command"
		}
		t.Run(name, func(t *testing.T) {
			outerLocal, outerPeer := net.Pipe()
			defer outerPeer.Close()
			directLocal, directPeer := net.Pipe()
			defer directPeer.Close()
			outer := &observedConn{Conn: outerLocal, writeStarted: make(chan struct{})}
			direct := &observedConn{Conn: directLocal}
			c := newTestConn(t, outer, direct)
			hello := make([]byte, 79)
			copy(hello, []byte{22, 3, 3, 0, 74, 2})
			hello[44] = 0x13
			hello[45] = 1
			copy(hello[60:], tls13SupportedVersions)
			c.FilterTLS(hello)
			payload := []byte{23, 3, 3, 0, 2, 1, 2}
			written := make(chan error, 1)
			go func() { _, err := c.Write(payload); written <- err }()
			waitStarted(t, outer.writeStarted)
			if c.WriterReplaceable() || N.UnwrapWriter(c) != c {
				t.Fatal("writer replaced before direct command was sent")
			}
			if closing {
				closed := make(chan error, 1)
				go func() { closed <- c.Close() }()
				waitResult(t, closed)
				if direct.closes.Load() != 1 || outer.closes.Load() != 0 {
					t.Fatal("pending direct close used TLS wrapper")
				}
				outerPeer.Close()
				select {
				case err := <-written:
					if err == nil {
						t.Fatal("closed command succeeded")
					}
				case <-time.After(3 * time.Second):
					t.Fatal("write did not finish")
				}
				return
			}
			cmd, data, err := readVisionFrame(outerPeer, true)
			if err != nil {
				t.Fatal(err)
			}
			if cmd != commandPaddingDirect || !bytes.Equal(data, payload) {
				t.Fatal("invalid direct command")
			}
			waitResult(t, written)
			if !c.WriterReplaceable() || N.UnwrapWriter(c) != direct {
				t.Fatal("writer did not become replaceable")
			}
			if N.UnwrapReader(c) != c {
				t.Fatal("write transition replaced read direction")
			}
			result := make(chan error, 1)
			go func() { _, err := c.Write([]byte("raw")); result <- err }()
			var raw [3]byte
			if _, err := io.ReadFull(directPeer, raw[:]); err != nil {
				t.Fatal(err)
			}
			waitResult(t, result)
			if string(raw[:]) != "raw" {
				t.Fatal("raw write changed")
			}
		})
	}
}

func TestVisionCloseReleasesRemainingReadBuffer(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	c := newTestConn(t, local, local)
	sent := make(chan error, 1)
	go func() {
		_, err := peer.Write(visionFrame(true, commandPaddingContinue, []byte("remainder")))
		sent <- err
	}()
	var p [1]byte
	if _, err := c.Read(p[:]); err != nil {
		t.Fatal(err)
	}
	if c.readRemainingBuffer == nil {
		t.Fatal("fixture did not retain unread data")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if c.readRemainingBuffer != nil {
		t.Fatal("closed connection retained pooled data")
	}
	// Close may interrupt the peer while it is still writing the trailing padding.
	select {
	case <-sent:
	case <-time.After(3 * time.Second):
		t.Fatal("peer stayed blocked")
	}
}

func TestVisionConcurrentCallers(t *testing.T) {
	for _, writing := range []bool{false, true} {
		name := "readers"
		if writing {
			name = "writers"
		}
		t.Run(name, func(t *testing.T) {
			local, peer := net.Pipe()
			defer peer.Close()
			c := newTestConn(t, local, local)
			const count = 24
			const size = 64
			results := make(chan error, count)
			received := make(chan byte, count)
			remote := make(chan error, 1)
			go func() {
				padded := true
				for i := 0; i < count; i++ {
					if writing {
						var data []byte
						var err error
						if padded {
							var cmd byte
							cmd, data, err = readVisionFrame(peer, i == 0)
							padded = cmd == commandPaddingContinue
						} else {
							data = make([]byte, size)
							_, err = io.ReadFull(peer, data)
						}
						if err != nil {
							remote <- err
							return
						}
						if len(data) != size || !bytes.Equal(data, bytes.Repeat(data[:1], size)) {
							remote <- errors.New("interleaved writer frames")
							return
						}
						received <- data[0]
					} else {
						frame := visionFrame(i == 0, commandPaddingContinue, bytes.Repeat([]byte{byte(i)}, size))
						headerStart := 0
						if i == 0 {
							headerStart = 16
						}
						frame[headerStart+3], frame[headerStart+4] = 0, 0
						if _, err := peer.Write(frame[:len(frame)-3]); err != nil {
							remote <- err
							return
						}
					}
				}
				remote <- nil
			}()
			for i := 0; i < count; i++ {
				go func() {
					if writing {
						_, err := c.Write(bytes.Repeat([]byte{byte(i)}, size))
						results <- err
					} else {
						data := make([]byte, size)
						_, err := io.ReadFull(c, data)
						if err == nil {
							if !bytes.Equal(data, bytes.Repeat(data[:1], size)) {
								err = errors.New("interleaved reader frames")
							} else {
								received <- data[0]
							}
						}
						results <- err
					}
				}()
			}
			for i := 0; i < count; i++ {
				waitResult(t, results)
			}
			waitResult(t, remote)
			seen := make(map[byte]bool)
			for i := 0; i < count; i++ {
				select {
				case value := <-received:
					seen[value] = true
				default:
					t.Fatal("missing payload")
				}
			}
			if len(seen) != count {
				t.Fatal("duplicated or lost concurrent payload")
			}
		})
	}
}

func TestVisionLargeDirectWriteKeepsReplacement(t *testing.T) {
	outerLocal, outerPeer := net.Pipe()
	defer outerPeer.Close()
	directLocal, directPeer := net.Pipe()
	defer directPeer.Close()
	c := newTestConn(t, outerLocal, directLocal)
	hello := make([]byte, 79)
	copy(hello, []byte{22, 3, 3, 0, 74, 2})
	hello[44], hello[45] = 0x13, 1
	copy(hello[60:], tls13SupportedVersions)
	c.FilterTLS(hello)
	payload := bytes.Repeat([]byte{'p'}, 20000)
	copy(payload, []byte{23, 3, 3})
	binary.BigEndian.PutUint16(payload[3:5], uint16(len(payload)-5))
	written := make(chan error, 1)
	go func() { _, err := c.Write(payload); written <- err }()
	cmd, first, err := readVisionFrame(outerPeer, true)
	if err != nil {
		t.Fatal(err)
	}
	if cmd != commandPaddingDirect || len(first) >= len(payload) {
		t.Fatal("fixture did not split the direct write")
	}
	remainder := make([]byte, len(payload)-len(first))
	if _, err := io.ReadFull(directPeer, remainder); err != nil {
		t.Fatal(err)
	}
	waitResult(t, written)
	if !bytes.Equal(append(first, remainder...), payload) {
		t.Fatal("direct write lost or reordered bytes")
	}
	if !c.WriterReplaceable() || N.UnwrapWriter(c) != directLocal {
		t.Fatal("later chunks reversed the direct writer state")
	}
}
