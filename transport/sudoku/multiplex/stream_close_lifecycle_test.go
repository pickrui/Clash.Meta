package multiplex

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

type closeBlockedConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (c *closeBlockedConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Write(p)
}

func TestStreamCloseReleasesBlockedSend(t *testing.T) {
	left, peer := net.Pipe()
	raw := &closeBlockedConn{Conn: left, started: make(chan struct{})}
	session := &Session{conn: raw, streams: make(map[uint32]*stream), closed: make(chan struct{})}
	stream := newStream(session, 1)
	session.registerStream(stream)
	var workers sync.WaitGroup
	t.Cleanup(func() { left.Close(); peer.Close(); workers.Wait(); session.Close() })
	wrote := make(chan error, 1)
	workers.Add(1)
	go func() {
		defer workers.Done()
		_, err := stream.Write(bytes.Repeat([]byte("blocked"), 1024))
		wrote <- err
	}()
	select {
	case <-raw.started:
	case <-time.After(time.Second):
		t.Fatal("stream did not begin physical frame write")
	}
	read := make(chan error, 1)
	workers.Add(1)
	go func() { defer workers.Done(); _, err := stream.Read(make([]byte, 1)); read <- err }()
	closed := make(chan error, 1)
	workers.Add(1)
	go func() { defer workers.Done(); closed <- stream.Close() }()
	timer := time.NewTimer(6 * time.Second)
	defer timer.Stop()
	gotClose, gotWrite, gotRead := false, false, false
	for !gotClose || !gotWrite || !gotRead {
		select {
		case <-closed:
			gotClose = true
		case err := <-wrote:
			gotWrite = true
			if err == nil {
				t.Error("cancelled blocked Write succeeded")
			}
		case err := <-read:
			gotRead = true
			if err == nil || err == io.EOF {
				t.Errorf("cancelled Read error = %v", err)
			}
		case <-timer.C:
			t.Fatalf("stream Close did not interrupt I/O: close=%v write=%v read=%v", gotClose, gotWrite, gotRead)
		}
	}
}

func TestStreamCloseBoundsItsOwnControlWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		left, peer := net.Pipe()
		session := &Session{conn: left, streams: make(map[uint32]*stream), closed: make(chan struct{})}
		defer peer.Close()
		defer session.Close()
		stream := newStream(session, 1)
		session.registerStream(stream)
		started := time.Now()
		if err := stream.Close(); err != nil {
			t.Fatal(err)
		}
		if elapsed := time.Since(started); elapsed != 5*time.Second {
			t.Fatalf("control write cleanup took %v", elapsed)
		}
		if !session.IsClosed() || !errors.Is(session.closedErr(), errMuxStreamCloseTimeout) {
			t.Fatalf("stalled session state: closed=%v err=%v", session.IsClosed(), session.closedErr())
		}
	})
}

func TestStreamClosePreservesQueuedDataAndOtherStreams(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		left, peer := net.Pipe()
		session := &Session{conn: left, streams: make(map[uint32]*stream), closed: make(chan struct{})}
		defer peer.Close()
		defer session.Close()
		first, second := newStream(session, 1), newStream(session, 2)
		session.registerStream(first)
		session.registerStream(second)
		session.writeMu.Lock()
		if _, err := first.Write([]byte("queued")); err != nil {
			t.Fatal(err)
		}
		if err := first.Close(); err != nil {
			t.Fatal(err)
		}
		session.writeMu.Unlock()
		type frame struct {
			kind    byte
			id      uint32
			payload string
		}
		frames := make(chan frame, 4)
		go func() {
			for {
				var header [headerSize]byte
				if _, err := io.ReadFull(peer, header[:]); err != nil {
					return
				}
				payload := make([]byte, binary.BigEndian.Uint32(header[5:9]))
				if _, err := io.ReadFull(peer, payload); err != nil {
					return
				}
				frames <- frame{header[0], binary.BigEndian.Uint32(header[1:5]), string(payload)}
			}
		}()
		if err := session.flushPending(true); err != nil {
			t.Fatal(err)
		}
		if got := <-frames; got != (frame{frameData, 1, "queued"}) {
			t.Fatalf("first frame = %+v", got)
		}
		if got := <-frames; got != (frame{frameClose, 1, ""}) {
			t.Fatalf("close frame = %+v", got)
		}
		if err := first.Close(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(6 * time.Second)
		if session.IsClosed() {
			t.Fatalf("completed close later canceled healthy session: %v", session.closedErr())
		}
		if _, err := second.Write([]byte("healthy")); err != nil {
			t.Fatal(err)
		}
		if got := <-frames; got != (frame{frameData, 2, "healthy"}) {
			t.Fatalf("second stream frame = %+v", got)
		}
		select {
		case got := <-frames:
			t.Fatalf("extra frame = %+v", got)
		default:
		}
	})
}

func TestStreamCloseResumesCurrentFrameAndPreservesOtherStream(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		left, peer := net.Pipe()
		raw := &closeBlockedConn{Conn: left, started: make(chan struct{})}
		session := &Session{conn: raw, streams: make(map[uint32]*stream), closed: make(chan struct{})}
		defer peer.Close()
		defer session.Close()
		first, second := newStream(session, 1), newStream(session, 2)
		session.registerStream(first)
		session.registerStream(second)
		payload := bytes.Repeat([]byte{'a'}, maxDataPayload+32)
		type writeResult struct {
			n   int
			err error
		}
		wrote := make(chan writeResult, 1)
		go func() { n, err := first.Write(payload); wrote <- writeResult{n, err} }()
		<-raw.started
		read := make(chan error, 1)
		go func() { _, err := first.Read(make([]byte, 1)); read <- err }()
		closed := make(chan error, 1)
		go func() { closed <- first.Close() }()
		if err := <-read; !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("local Read did not terminate: %v", err)
		}
		select {
		case result := <-wrote:
			t.Fatalf("Write returned before physical frame completed: %+v", result)
		default:
		}
		var header [headerSize]byte
		if _, err := io.ReadFull(peer, header[:]); err != nil {
			t.Fatal(err)
		}
		if header[0] != frameData || binary.BigEndian.Uint32(header[5:9]) != maxDataPayload {
			t.Fatalf("current frame header = %x", header)
		}
		got := make([]byte, maxDataPayload)
		if _, err := io.ReadFull(peer, got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, payload[:maxDataPayload]) {
			t.Fatal("current frame was truncated or changed")
		}
		result := <-wrote
		if result.n != maxDataPayload || !errors.Is(result.err, io.ErrClosedPipe) {
			t.Fatalf("Write after Close = %+v", result)
		}
		if _, err := io.ReadFull(peer, header[:]); err != nil {
			t.Fatal(err)
		}
		if header[0] != frameClose || binary.BigEndian.Uint32(header[1:5]) != 1 || binary.BigEndian.Uint32(header[5:9]) != 0 {
			t.Fatalf("frame after current DATA = %x", header)
		}
		if err := <-closed; err != nil {
			t.Fatal(err)
		}
		time.Sleep(6 * time.Second)
		go func() { n, err := second.Write([]byte("healthy")); wrote <- writeResult{n, err} }()
		if _, err := io.ReadFull(peer, header[:]); err != nil {
			t.Fatal(err)
		}
		if header[0] != frameData || binary.BigEndian.Uint32(header[1:5]) != 2 {
			t.Fatalf("second stream frame = %x", header)
		}
		got = make([]byte, binary.BigEndian.Uint32(header[5:9]))
		if _, err := io.ReadFull(peer, got); err != nil {
			t.Fatal(err)
		}
		result = <-wrote
		if string(got) != "healthy" || result.err != nil || result.n != len(got) || session.IsClosed() {
			t.Fatalf("second stream data=%q result=%+v closed=%v", got, result, session.IsClosed())
		}
	})
}

func TestStreamCloseWriteReleasesStalledIO(t *testing.T) {
	for _, activeWrite := range []bool{false, true} {
		t.Run(map[bool]string{false: "control", true: "active-write"}[activeWrite], func(t *testing.T) {
			run := func(t *testing.T) {
				left, peer := net.Pipe()
				raw := &closeBlockedConn{Conn: left, started: make(chan struct{})}
				session := &Session{conn: raw, streams: make(map[uint32]*stream), closed: make(chan struct{})}
				defer peer.Close()
				defer session.Close()
				stream := newStream(session, 1)
				session.registerStream(stream)
				readDone := make(chan error, 1)
				go func() { _, err := stream.Read(make([]byte, 1)); readDone <- err }()
				writeDone := make(chan error, 1)
				if activeWrite {
					go func() { _, err := stream.Write(bytes.Repeat([]byte("blocked"), 1024)); writeDone <- err }()
					<-raw.started
				}
				closed := make(chan error, 1)
				go func() { closed <- stream.CloseWrite() }()
				if !activeWrite {
					<-raw.started
				}
				finished := false
				select {
				case err := <-closed:
					finished = true
					if err == nil && !session.IsClosed() {
						t.Error("stalled CloseWrite succeeded")
					}
				case <-time.After(6 * time.Second):
					t.Error("CloseWrite did not release stalled stream I/O")
				}
				readFinished := false
				if finished {
					select {
					case err := <-readDone:
						readFinished = true
						if err == nil {
							t.Error("stalled Read succeeded")
						}
					case <-time.After(time.Second):
						t.Error("failed CloseWrite left the opposite Read blocked")
					}
				}
				_ = left.Close()
				_ = peer.Close()
				if !finished {
					<-closed
				}
				if !readFinished {
					<-readDone
				}
				if activeWrite {
					<-writeDone
				}
			}
			if activeWrite {
				run(t)
			} else {
				synctest.Test(t, run)
			}
		})
	}
}

func TestStreamCloseWritePreservesReadAndOtherStreamsAfterBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		left, peer := net.Pipe()
		session, err := NewClientSession(left)
		if err != nil {
			t.Fatal(err)
		}
		defer session.Close()
		defer peer.Close()
		first, second := newStream(session, 1), newStream(session, 2)
		session.registerStream(first)
		session.registerStream(second)
		type frame struct {
			kind    byte
			id      uint32
			payload string
		}
		frames := make(chan frame, 4)
		go func() {
			for {
				var header [headerSize]byte
				if _, err := io.ReadFull(peer, header[:]); err != nil {
					return
				}
				payload := make([]byte, binary.BigEndian.Uint32(header[5:9]))
				if _, err := io.ReadFull(peer, payload); err != nil {
					return
				}
				frames <- frame{header[0], binary.BigEndian.Uint32(header[1:5]), string(payload)}
			}
		}()
		if err := first.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		if err := first.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		if got := <-frames; got != (frame{frameClose, 1, ""}) {
			t.Fatalf("half-close frame = %+v", got)
		}
		time.Sleep(6 * time.Second)
		if session.IsClosed() {
			t.Fatalf("completed half-close canceled session: %v", session.closedErr())
		}
		response := []byte("response")
		delivered := make(chan error, 1)
		go func() {
			var header [headerSize]byte
			putHeader(header[:], frameData, 1, len(response))
			_, err := peer.Write(append(header[:], response...))
			delivered <- err
		}()
		got := make([]byte, len(response))
		if _, err := io.ReadFull(first, got); err != nil || !bytes.Equal(got, response) {
			t.Fatalf("half-closed response=%q err=%v", got, err)
		}
		if err := <-delivered; err != nil {
			t.Fatal(err)
		}
		if _, err := second.Write([]byte("healthy")); err != nil {
			t.Fatal(err)
		}
		if got := <-frames; got != (frame{frameData, 2, "healthy"}) {
			t.Fatalf("second stream frame = %+v", got)
		}
	})
}
