package packet

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
)

type deferredPacketConn struct {
	net.PacketConn
	started    chan struct{}
	release    chan struct{}
	payload    []byte
	readErr    error
	bufferSize int
	bufferOnly bool
}

func (c *deferredPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	c.bufferSize = len(buffer)
	return c.read(func(int) []byte { return buffer })
}

func (c *deferredPacketConn) ReadFromWithBuffer(getBuffer func(int) []byte) (int, net.Addr, error) {
	return c.read(getBuffer)
}

func (c *deferredPacketConn) read(getBuffer func(int) []byte) (int, net.Addr, error) {
	close(c.started)
	<-c.release
	address := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	if c.payload == nil {
		return 0, address, c.readErr
	}
	buffer := getBuffer(len(c.payload))
	c.bufferSize = len(buffer)
	if c.bufferOnly {
		return 0, address, c.readErr
	}
	return copy(buffer, c.payload), address, c.readErr
}

func TestWaitReadFromDefersBufferUntilPacketArrives(t *testing.T) {
	conn := &deferredPacketConn{
		started: make(chan struct{}), release: make(chan struct{}),
		payload: []byte("datagram"),
	}
	packetConn := NewEnhancePacketConn(conn)
	done := make(chan struct{})
	var data []byte
	var put func()
	var address net.Addr
	var err error
	go func() {
		defer close(done)
		data, put, address, err = packetConn.WaitReadFrom()
	}()
	<-conn.started
	waitingBufferSize := conn.bufferSize
	close(conn.release)
	<-done
	if put != nil {
		defer put()
	}
	if waitingBufferSize != 0 {
		t.Errorf("waiting read retained a %d-byte buffer", waitingBufferSize)
	}
	if conn.bufferSize != len(conn.payload) {
		t.Errorf("read buffer = %d bytes, want payload size %d", conn.bufferSize, len(conn.payload))
	}
	if err != nil || string(data) != string(conn.payload) || put == nil || address.String() != "127.0.0.1:1234" {
		t.Fatalf("read = %q, %v, releasable=%v, %v", data, address, put != nil, err)
	}
}

func TestWaitReadFromPreservesPacketAndErrorOwnership(t *testing.T) {
	for _, tc := range []struct {
		name       string
		payload    []byte
		readErr    error
		bufferOnly bool
	}{
		{name: "large_datagram", payload: bytes.Repeat([]byte{0x42}, 24*1024)},
		{name: "data_and_error", payload: []byte("last packet"), readErr: io.EOF},
		{name: "empty_datagram", payload: []byte{}},
		{name: "closed_before_allocation", readErr: net.ErrClosed},
		{name: "closed_after_allocation", payload: []byte("discarded"), readErr: net.ErrClosed, bufferOnly: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := &deferredPacketConn{
				started: make(chan struct{}), release: make(chan struct{}),
				payload: tc.payload, readErr: tc.readErr, bufferOnly: tc.bufferOnly,
			}
			close(conn.release)
			data, put, address, err := NewEnhancePacketConn(conn).WaitReadFrom()
			if put != nil {
				defer put()
			}
			if !errors.Is(err, tc.readErr) || address.String() != "127.0.0.1:1234" {
				t.Fatalf("read address/error = %v, %v", address, err)
			}
			if len(tc.payload) > 0 && !tc.bufferOnly {
				if string(data) != string(tc.payload) || put == nil {
					t.Fatalf("packet lost with error: %q, releasable=%v", data, put != nil)
				}
			} else if data != nil || put != nil {
				t.Fatalf("empty read retained a buffer: %v, releasable=%v", data, put != nil)
			}
		})
	}
}

func TestWaitReadFromPreservesPlainPacketConnFallback(t *testing.T) {
	conn := &deferredPacketConn{
		started: make(chan struct{}), release: make(chan struct{}),
		payload: []byte("plain packet"),
	}
	close(conn.release)
	plain := struct{ net.PacketConn }{conn}
	data, put, _, err := NewEnhancePacketConn(plain).WaitReadFrom()
	if put != nil {
		defer put()
	}
	if err != nil || string(data) != string(conn.payload) || put == nil {
		t.Fatalf("plain read = %q, releasable=%v, %v", data, put != nil, err)
	}
}
