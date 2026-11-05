package mux

import (
	"errors"
	"net"
	"sync"
	"testing"
)

type countedCloseConn struct {
	net.Conn
	mutex sync.Mutex
	calls int
	err   error
}

func (c *countedCloseConn) Close() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.calls++
	return c.err
}

// The HTTP/2 serve loop and the owning mux service can close the same session.
func TestH2MuxServerConcurrentClose(t *testing.T) {
	failure := errors.New("test close result")
	conn := &countedCloseConn{err: failure}
	session := &h2MuxServerSession{conn: conn, done: make(chan struct{})}
	var workers sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 64; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() {
				if failure := recover(); failure != nil {
					t.Errorf("concurrent Close panicked: %v", failure)
				}
			}()
			<-start
			if err := session.Close(); !errors.Is(err, failure) {
				t.Errorf("Close = %v", err)
			}
		}()
	}
	close(start)
	workers.Wait()
	if !session.IsClosed() {
		t.Fatal("session is still open")
	}
	if conn.calls != 1 {
		t.Fatalf("underlying Close called %d times, want 1", conn.calls)
	}
	if err := session.Close(); !errors.Is(err, failure) {
		t.Fatalf("repeat Close = %v", err)
	}
	if conn.calls != 1 {
		t.Fatalf("repeat Close called underlying connection again: %d", conn.calls)
	}
}
