package tls

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type restlsWriteCallbackConn struct {
	net.Conn
	write func([]byte) (int, error)
}

func (c *restlsWriteCallbackConn) Write(p []byte) (int, error) { return c.write(p) }

func TestRestlsServerEarlyClientResponseDuringWrite(t *testing.T) {
	state := newRestlsServerUnitState(t, "1<1,1")
	defer state.close()
	var writes atomic.Int32
	conn := &restlsWriteCallbackConn{write: func(p []byte) (int, error) {
		if writes.Add(1) == 1 {
			state.noteClientRecord()
		}
		return len(p), nil
	}}
	done := make(chan error, 1)
	go func() { done <- state.writeRestlsRecords(conn, []byte("ab")) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		state.close()
		<-done
		t.Fatal("reply received before socket Write returned was lost")
	}
	if writes.Load() != 2 {
		t.Fatalf("wrote %d records, want 2", writes.Load())
	}
}

func TestRestlsServerControlResponseWhileDataWaits(t *testing.T) {
	state := newRestlsServerUnitState(t, "1<1,1")
	defer state.close()
	first := make(chan struct{})
	var writes atomic.Int32
	conn := &restlsWriteCallbackConn{write: func(p []byte) (int, error) {
		switch writes.Add(1) {
		case 1:
			close(first)
		case 2:
			state.noteClientRecord()
		}
		return len(p), nil
	}}
	dataDone, controlDone := make(chan error, 1), make(chan error, 1)
	go func() { dataDone <- state.writeRestlsRecords(conn, []byte("ab")) }()
	<-first
	// The peer's pending response needs a server control record before it can
	// acknowledge the scripted application record. Control I/O must remain live.
	go func() { controlDone <- state.writeRestlsRecords(conn, nil) }()
	select {
	case err := <-controlDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		state.close()
		<-dataDone
		<-controlDone
		t.Fatal("application flow-control wait blocked the control response")
	}
	if err := waitRestlsServerDone(t, dataDone); err != nil {
		t.Fatal(err)
	}
	if writes.Load() != 3 {
		t.Fatalf("wrote %d records, want 3", writes.Load())
	}
}
