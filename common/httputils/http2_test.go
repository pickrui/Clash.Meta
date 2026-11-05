package httputils

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/http/http2"
)

type failedHTTP2Conn struct {
	prefix   *bytes.Reader
	readErr  error
	failures atomic.Int32
	closed   chan struct{}
	once     sync.Once
}

func (c *failedHTTP2Conn) Read(p []byte) (int, error) {
	if c.prefix.Len() > 0 {
		return c.prefix.Read(p)
	}
	// Bound the old read loop so a regression fails without spinning indefinitely.
	if c.failures.Add(1) > 8 {
		return 0, io.EOF
	}
	return 0, c.readErr
}
func (c *failedHTTP2Conn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *failedHTTP2Conn) Close() error                     { c.once.Do(func() { close(c.closed) }); return nil }
func (c *failedHTTP2Conn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *failedHTTP2Conn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *failedHTTP2Conn) SetDeadline(time.Time) error      { return nil }
func (c *failedHTTP2Conn) SetReadDeadline(time.Time) error  { return nil }
func (c *failedHTTP2Conn) SetWriteDeadline(time.Time) error { return nil }

func TestHTTP2TransportStopsOnUnderlyingStreamError(t *testing.T) {
	var preface bytes.Buffer
	if err := http2.NewFramer(&preface, nil).WriteSettings(); err != nil {
		t.Fatal(err)
	}
	conn := &failedHTTP2Conn{prefix: bytes.NewReader(preface.Bytes()), readErr: http2.StreamError{StreamID: 1, Code: http2.ErrCodeCancel}, closed: make(chan struct{})}
	client, err := (&http2.Transport{}).NewClientConn(conn)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	select {
	case <-conn.closed:
	case <-time.After(3 * time.Second):
		t.Fatal("HTTP/2 read loop did not close the failed connection")
	}
	if got := conn.failures.Load(); got != 1 {
		t.Fatalf("retried a terminal underlying stream error %d times", got)
	}
}

func TestHTTP2FramerPreservesErrorIdentity(t *testing.T) {
	cause := errors.New("outer tunnel failed")
	underlying := http2.StreamError{StreamID: 3, Code: http2.ErrCodeCancel, Cause: cause}
	conn := &failedHTTP2Conn{prefix: bytes.NewReader(nil), readErr: underlying, closed: make(chan struct{})}
	_, err := http2.NewFramer(io.Discard, conn).ReadFrame()
	if _, direct := err.(http2.StreamError); direct {
		t.Fatal("underlying error misclassified as a frame-local stream error")
	}
	var streamErr http2.StreamError
	if !errors.As(err, &streamErr) || streamErr.StreamID != 3 || streamErr.Cause != cause {
		t.Fatalf("lost underlying error identity: %v", err)
	}
	_, err = http2.NewFramer(io.Discard, bytes.NewReader(nil)).ReadFrame()
	if err != io.EOF {
		t.Fatalf("EOF changed: %v", err)
	}
	// A malformed frame on this connection must remain a frame-local error.
	var malformed bytes.Buffer
	if err := http2.NewFramer(&malformed, nil).WriteRawFrame(http2.FrameWindowUpdate, 0, 1, []byte{0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	_, err = http2.NewFramer(io.Discard, &malformed).ReadFrame()
	if _, direct := err.(http2.StreamError); !direct {
		t.Fatalf("local frame error changed: %v", err)
	}
}
