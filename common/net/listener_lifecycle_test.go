package net

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type queuedTestListener struct {
	conn chan net.Conn
	done chan struct{}
	once sync.Once
}

func (l *queuedTestListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conn:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *queuedTestListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *queuedTestListener) Addr() net.Addr { return &net.TCPAddr{} }

type handshakeTrackedConn struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func (c *handshakeTrackedConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.Conn.Close()
}

func TestHandleListenerCloseReleasesBlockedHandshake(t *testing.T) {
	raw, peer := net.Pipe()
	defer raw.Close()
	defer peer.Close()
	base := &queuedTestListener{conn: make(chan net.Conn, 1), done: make(chan struct{})}
	base.conn <- raw
	entered := make(chan struct{})
	finished := make(chan struct{})
	l := NewHandleContextListener(context.Background(), base, func(ctx context.Context, c net.Conn) (net.Conn, error) {
		close(entered)
		defer close(finished)
		_, err := io.ReadFull(c, make([]byte, 1))
		return nil, err
	}, nil)
	defer l.Close()
	accepted := make(chan struct{})
	go func() { _, _ = l.Accept(); close(accepted) }()
	<-entered
	_ = l.Close()
	select {
	case <-finished:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Close left handshake blocked on its socket")
	}
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("Accept blocked after close")
	}
}

func TestHandleListenerCloseRejectsLateSuccess(t *testing.T) {
	raw, peer := net.Pipe()
	defer raw.Close()
	defer peer.Close()
	tracked := &handshakeTrackedConn{Conn: raw, done: make(chan struct{})}
	base := &queuedTestListener{conn: make(chan net.Conn, 1), done: make(chan struct{})}
	base.conn <- tracked
	entered, release := make(chan struct{}), make(chan struct{})
	panics := make(chan any, 1)
	l := NewHandleContextListener(context.Background(), base, func(context.Context, net.Conn) (net.Conn, error) { close(entered); <-release; return tracked, nil }, func(v any) { panics <- v })
	defer l.Close()
	accepted := make(chan struct{})
	go func() {
		c, _ := l.Accept()
		if c != nil {
			_ = c.Close()
		}
		close(accepted)
	}()
	<-entered
	_ = l.Close()
	close(release)
	select {
	case <-tracked.done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("late handshake connection was not closed")
	}
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("Accept blocked after close")
	}
	select {
	case v := <-panics:
		t.Fatalf("late result panicked: %v", v)
	default:
	}
}

func TestHandleListenerHandoffSurvivesListenerClose(t *testing.T) {
	raw, peer := net.Pipe()
	defer peer.Close()
	base := &queuedTestListener{conn: make(chan net.Conn, 1), done: make(chan struct{})}
	base.conn <- raw
	var acceptedContext context.Context
	l := NewHandleContextListener(context.Background(), base, func(ctx context.Context, c net.Conn) (net.Conn, error) { acceptedContext = ctx; return c, nil }, nil)
	defer l.Close()
	conn, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := acceptedContext.Err(); err != nil {
		t.Fatalf("accepted connection cancelled with listener: %v", err)
	}
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	written := make(chan error, 1)
	go func() { _, err := peer.Write([]byte("ok")); written <- err }()
	p := make([]byte, 2)
	if _, err := io.ReadFull(conn, p); err != nil {
		t.Fatal(err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if acceptedContext.Err() == nil {
		t.Fatal("closing accepted connection retained its handshake context")
	}
}

func TestHandleListenerParentCancellationClosesPendingSocket(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	raw, peer := net.Pipe()
	defer raw.Close()
	defer peer.Close()
	base := &queuedTestListener{conn: make(chan net.Conn, 1), done: make(chan struct{})}
	base.conn <- raw
	entered, finished := make(chan struct{}), make(chan struct{})
	l := NewHandleContextListener(ctx, base, func(ctx context.Context, c net.Conn) (net.Conn, error) {
		close(entered)
		defer close(finished)
		_, err := io.ReadFull(c, make([]byte, 1))
		return nil, err
	}, nil)
	defer l.Close()
	accepted := make(chan error, 1)
	go func() { _, err := l.Accept(); accepted <- err }()
	<-entered
	cancel()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("parent cancellation leaked pending handshake")
	}
	select {
	case err := <-accepted:
		if err == nil {
			t.Fatal("accepted after cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("Accept blocked")
	}
}
