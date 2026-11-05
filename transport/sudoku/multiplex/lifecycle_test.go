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

func sessionPair(t *testing.T) (*Session, *Session) {
	t.Helper()
	left, right := net.Pipe()
	_ = left.SetDeadline(time.Now().Add(5 * time.Second))
	_ = right.SetDeadline(time.Now().Add(5 * time.Second))
	client, err := NewClientSession(left)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServerSession(right)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return client, server
}

func streamPair(t *testing.T, client, server *Session) (*stream, *stream) {
	t.Helper()
	out, err := client.OpenStream(nil)
	if err != nil {
		t.Fatal(err)
	}
	in, _, err := server.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	return out.(*stream), in.(*stream)
}

func TestStreamCloseReadPreservesWriteAndDiscardsInput(t *testing.T) {
	client, server := sessionPair(t)
	out, in := streamPair(t, client, server)
	if _, err := in.Write([]byte("discard")); err != nil {
		t.Fatal(err)
	}
	if err := out.CloseRead(); err != nil {
		t.Fatal(err)
	}
	if _, err := in.Write([]byte("also discard")); err != nil {
		t.Fatal(err)
	}
	if _, err := out.Read(make([]byte, 1)); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("read after CloseRead: %v", err)
	}
	if _, err := out.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := out.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	request, err := io.ReadAll(in)
	if err != nil || string(request) != "request" {
		t.Fatalf("request=%q err=%v", request, err)
	}
	if err := in.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if client.getStream(out.id) != nil || server.getStream(in.id) != nil {
		t.Fatal("closed stream remained registered")
	}
}

func TestStreamReceiveQueueBoundaryAndReset(t *testing.T) {
	client, server := sessionPair(t)
	out, in := streamPair(t, client, server)
	// Fill exactly the limit, then round-trip another stream to observe that
	// the shared reader consumed all preceding DATA frames without resetting.
	payload := bytes.Repeat([]byte{'q'}, maxQueuedBytesPerStream)
	if n, err := out.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("fill=%d err=%v", n, err)
	}
	_, barrier := streamPair(t, client, server)
	if server.getStream(in.id) != in {
		t.Fatal("stream reset at the allowed queue limit")
	}
	in.mu.Lock()
	queued := in.queuedBytes
	in.mu.Unlock()
	if queued != len(payload) {
		t.Fatalf("queued=%d want=%d", queued, len(payload))
	}
	if _, err := out.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	_, err := out.Read(make([]byte, 1))
	if err == nil || err.Error() != errMuxReceiveQueueFull.Error() {
		t.Fatalf("remote reset=%v", err)
	}
	retained, err := io.ReadAll(in)
	if !errors.Is(err, errMuxReceiveQueueFull) || !bytes.Equal(retained, payload) {
		t.Fatalf("retained=%d err=%v", len(retained), err)
	}
	if server.getStream(in.id) != nil {
		t.Fatal("reset stream remained registered")
	}
	if client.IsClosed() || server.IsClosed() {
		t.Fatal("overflow closed the shared session")
	}
	if _, err := barrier.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
}

func TestStreamCloseReleasesResetQueue(t *testing.T) {
	st := newStream(nil, 1)
	if err := st.enqueue(bytes.Repeat([]byte{1}, maxQueuedBytesPerStream)); err != nil {
		t.Fatal(err)
	}
	st.closeNoSend(errMuxReceiveQueueFull)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.queuedBytes != 0 || st.readBuf != nil || st.queue != nil {
		t.Fatalf("Close retained %d bytes after reset", st.queuedBytes)
	}
}

// Pause after delivering the first full DATA payload. The peer can send a
// RESET while the application Write still has additional frames to send.
type pausedPayloadConn struct {
	net.Conn
	written chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *pausedPayloadConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if len(p) == maxDataPayload {
		c.once.Do(func() { close(c.written); <-c.release })
	}
	return n, err
}

func TestStreamWriteStopsAfterResetBetweenFrames(t *testing.T) {
	left, peer := net.Pipe()
	_ = left.SetDeadline(time.Now().Add(5 * time.Second))
	_ = peer.SetDeadline(time.Now().Add(5 * time.Second))
	paused := &pausedPayloadConn{Conn: left, written: make(chan struct{}), release: make(chan struct{})}
	session, err := NewClientSession(paused)
	if err != nil {
		t.Fatal(err)
	}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(paused.release) }) }
	t.Cleanup(func() { release(); _ = session.Close(); _ = peer.Close() })
	st := newStream(session, 1)
	session.registerStream(st)
	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	go func() { n, err := st.Write(bytes.Repeat([]byte{7}, 2*maxDataPayload+17)); done <- result{n, err} }()
	var header [headerSize]byte
	if _, err := io.ReadFull(peer, header[:]); err != nil {
		t.Fatal(err)
	}
	if header[0] != frameData || binary.BigEndian.Uint32(header[5:]) != maxDataPayload {
		t.Fatal("invalid first data frame")
	}
	if _, err := io.CopyN(io.Discard, peer, maxDataPayload); err != nil {
		t.Fatal(err)
	}
	<-paused.written
	resetMessage := []byte("peer reset")
	header[0] = frameReset
	binary.BigEndian.PutUint32(header[1:5], st.id)
	binary.BigEndian.PutUint32(header[5:9], uint32(len(resetMessage)))
	if err := writeAllChunks(peer, header[:], resetMessage); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Read(make([]byte, 1)); err == nil || err.Error() != string(resetMessage) {
		t.Fatalf("reset not received: %v", err)
	}
	// Drain any invalid extra frames so the old implementation can return and
	// fail on the result, instead of leaving a blocked goroutine behind.
	drained := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, peer); close(drained) }()
	release()
	got := <-done
	_ = session.Close()
	<-drained
	if got.n != maxDataPayload || got.err == nil || got.err.Error() != string(resetMessage) {
		t.Fatalf("Write after reset: n=%d err=%v", got.n, got.err)
	}
}

func TestSessionCloseUnblocksPendingStreamOperations(t *testing.T) {
	left, peer := net.Pipe()
	blocked := &blockedWriteConn{Conn: left, started: make(chan struct{})}
	// No reader: the first header write remains blocked in the transport.
	session, err := NewClientSession(blocked)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close(); _ = peer.Close() })
	st := newStream(session, 1)
	session.registerStream(st)
	readDone := make(chan error, 1)
	writeDone := make(chan error, 1)
	go func() { _, err := st.Read(make([]byte, 1)); readDone <- err }()
	go func() { _, err := st.Write([]byte("blocked")); writeDone <- err }()
	<-blocked.started
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	for _, done := range []<-chan error{readDone, writeDone} {
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("operation succeeded after close")
			}
		case <-time.After(time.Second):
			t.Fatal("session close did not release operation")
		}
	}
	select {
	case <-session.Done():
	default:
		t.Fatal("Done not closed")
	}
}

type blockedWriteConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (c *blockedWriteConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Write(p)
}

func TestSessionKeepaliveOnlyWhenIdleAndStops(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		left, peer := net.Pipe()
		session, err := NewClientSession(left)
		if err != nil {
			t.Fatal(err)
		}
		defer session.Close()
		defer peer.Close()
		frames := make(chan uint32, 8)
		go func() {
			for {
				var header [headerSize]byte
				if _, err := io.ReadFull(peer, header[:]); err != nil {
					return
				}
				n := binary.BigEndian.Uint32(header[5:9])
				if _, err := io.CopyN(io.Discard, peer, int64(n)); err != nil {
					return
				}
				frames <- binary.BigEndian.Uint32(header[1:5])
			}
		}()
		// Repeated starts must not add tickers or extra keepalive frames.
		session.startKeepalive(keepaliveInterval)
		synctest.Wait()
		time.Sleep(keepaliveInterval - time.Second)
		if err := session.sendFrame(frameData, 1, []byte("active")); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if id := <-frames; id != 1 {
			t.Fatalf("active frame id=%d", id)
		}
		time.Sleep(time.Second)
		synctest.Wait()
		select {
		case id := <-frames:
			t.Fatalf("keepalive while active, id=%d", id)
		default:
		}
		time.Sleep(keepaliveInterval)
		synctest.Wait()
		select {
		case id := <-frames:
			if id != 0 {
				t.Fatalf("keepalive id=%d", id)
			}
		default:
			t.Fatal("missing idle keepalive")
		}
		_ = session.Close()
		synctest.Wait()
		time.Sleep(2 * keepaliveInterval)
		synctest.Wait()
		select {
		case id := <-frames:
			t.Fatalf("frame after close: %d", id)
		default:
		}
		select {
		case <-session.Done():
		default:
			t.Fatal("Done not closed")
		}
		// synctest also waits for all session and peer goroutines to exit.
	})
}
