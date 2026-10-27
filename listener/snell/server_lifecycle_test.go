package snell

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/transport/shadowsocks/shadowaead"
	S "github.com/metacubex/mihomo/transport/snell"
)

type requestIOConn struct {
	net.Conn
	readStarted  chan struct{}
	writeStarted chan struct{}
	forwardZero  bool
	readOnce     sync.Once
	writeOnce    sync.Once
}

func (c *requestIOConn) Read(p []byte) (int, error) {
	c.readOnce.Do(func() { close(c.readStarted) })
	return c.Conn.Read(p)
}

func (c *requestIOConn) Write(p []byte) (int, error) {
	if len(p) == 0 && !c.forwardZero {
		return 0, nil
	}
	c.writeOnce.Do(func() { close(c.writeStarted) })
	return c.Conn.Write(p)
}

type requestEOFReader struct{}

func (requestEOFReader) Read([]byte) (int, error) { return 0, shadowaead.ErrZeroChunk }

func TestRequestCloseReleasesInFlightIO(t *testing.T) {
	for _, operation := range []string{"read", "write"} {
		t.Run(operation, func(t *testing.T) {
			raw, peer := net.Pipe()
			defer raw.Close()
			defer peer.Close()
			conn := &requestIOConn{Conn: raw, readStarted: make(chan struct{}), writeStarted: make(chan struct{})}
			request := &tcpRequestConn{Conn: conn, reader: bufio.NewReader(conn), reuse: true, replyWritten: true}
			if operation == "write" {
				request.reader = bufio.NewReader(requestEOFReader{})
				if _, err := request.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
					t.Fatal(err)
				}
			}
			ioDone := make(chan error, 1)
			go func() {
				var err error
				if operation == "read" {
					_, err = request.Read(make([]byte, 1))
				} else {
					_, err = request.Write([]byte("blocked"))
				}
				ioDone <- err
			}()
			if operation == "read" {
				<-conn.readStarted
			} else {
				<-conn.writeStarted
			}
			closed := make(chan error, 1)
			go func() { closed <- request.Close() }()
			closeFinished, ioFinished := false, false
			timeout := time.NewTimer(time.Second)
			defer timeout.Stop()
		wait:
			for !closeFinished || !ioFinished {
				select {
				case err := <-closed:
					closeFinished = true
					if err != nil {
						t.Errorf("Close: %v", err)
					}
				case err := <-ioDone:
					ioFinished = true
					if err == nil {
						t.Errorf("blocked %s completed without a close error", operation)
					}
				case <-timeout.C:
					t.Errorf("Close did not release in-flight %s (close returned=%v)", operation, closeFinished)
					break wait
				}
			}
			_ = raw.Close()
			_ = peer.Close()
			if !closeFinished {
				<-closed
			}
			if !ioFinished {
				<-ioDone
			}
		})
	}
}

func TestRequestCloseBoundsItsControlWrite(t *testing.T) {
	for _, mode := range []string{"error", "zero"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				raw, peer := net.Pipe()
				defer raw.Close()
				defer peer.Close()
				conn := &requestIOConn{Conn: raw, readStarted: make(chan struct{}), writeStarted: make(chan struct{}), forwardZero: true}
				request := &tcpRequestConn{Conn: conn, reader: bufio.NewReader(requestEOFReader{}), reuse: true, replyWritten: mode == "zero"}
				if mode == "zero" {
					if _, err := request.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
						t.Fatal(err)
					}
				}
				closed := make(chan error, 1)
				go func() { closed <- request.Close() }()
				<-conn.writeStarted
				finished := false
				select {
				case err := <-closed:
					finished = true
					var timeout net.Error
					if !errors.As(err, &timeout) || !timeout.Timeout() {
						t.Errorf("stalled control write error = %v", err)
					}
				case <-time.After(C.DefaultTCPTimeout + time.Second):
					t.Error("Close waited indefinitely for a peer that never reads")
				}
				_ = raw.Close()
				_ = peer.Close()
				if !finished {
					<-closed
				}
			})
		})
	}
}

type requestBoundaryReader struct{ reads int }

func (r *requestBoundaryReader) Read(p []byte) (int, error) {
	r.reads++
	if r.reads == 1 {
		return 0, shadowaead.ErrZeroChunk
	}
	return copy(p, "next-request"), nil
}

func TestRequestEOFKeepsItsBoundary(t *testing.T) {
	source := &requestBoundaryReader{}
	request := &tcpRequestConn{reader: bufio.NewReader(source), reuse: true}
	for round := 0; round < 2; round++ {
		if n, err := request.Read(make([]byte, 32)); n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("read after request EOF = %d, %v", n, err)
		}
	}
	if source.reads != 1 {
		t.Fatalf("finished request read the next request: %d reads", source.reads)
	}
}

func TestClosedRequestDoesNotChangeDeadlines(t *testing.T) {
	raw, peer := net.Pipe()
	defer raw.Close()
	defer peer.Close()
	conn := &requestIOConn{Conn: raw, readStarted: make(chan struct{}), writeStarted: make(chan struct{})}
	request := &tcpRequestConn{Conn: conn, reader: bufio.NewReader(requestEOFReader{}), reuse: true, replyWritten: true}
	if _, err := request.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if err := request.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := request.Close(); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		set  func(time.Time) error
	}{
		{"all", request.SetDeadline},
		{"read", request.SetReadDeadline},
		{"write", request.SetWriteDeadline},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.set(time.Now().Add(-time.Hour)); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("closed request changed the physical stream deadline: %v", err)
			}
		})
	}
}

type requestTestTunnel struct {
	C.Tunnel
	handle func(net.Conn)
}

func (t requestTestTunnel) HandleTCPConn(conn net.Conn, _ *C.Metadata) { t.handle(conn) }

func TestRequestHalfCloseAndReuse(t *testing.T) {
	for _, version := range []int{S.Version4, S.Version5} {
		for _, responseFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("v%d/response-first=%v", version, responseFirst), func(t *testing.T) {
				raw, peer := net.Pipe()
				_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
				_ = peer.SetDeadline(time.Now().Add(5 * time.Second))
				const key = "request-lifecycle-fixture"
				listener := &Listener{config: LC.SnellServer{Psk: key, Version: version}}
				results := make(chan error, 2)
				tunnel := requestTestTunnel{handle: func(conn net.Conn) {
					request := conn.(*tcpRequestConn)
					sendResponse := func() error {
						if _, err := conn.Write([]byte("response")); err != nil {
							return err
						}
						if responseFirst {
							return request.CloseWrite()
						}
						return nil
					}
					if responseFirst {
						if err := sendResponse(); err != nil {
							results <- err
							return
						}
					}
					data, err := io.ReadAll(conn)
					if err == nil && !bytes.Equal(data, []byte("request")) {
						err = fmt.Errorf("request = %q", data)
					}
					if err == nil && !responseFirst {
						err = sendResponse()
					}
					if err == nil {
						err = conn.SetDeadline(time.Now().Add(-time.Hour))
					}
					results <- errors.Join(err, conn.Close())
				}}
				serverDone := make(chan struct{})
				go func() { listener.HandleConn(raw, tunnel); close(serverDone) }()
				defer func() { _ = peer.Close(); _ = raw.Close(); <-serverDone }()
				client := S.StreamConn(peer, []byte(key), version)
				readResponse := func() {
					t.Helper()
					data, err := io.ReadAll(client)
					if !errors.Is(err, shadowaead.ErrZeroChunk) || !bytes.Equal(data, []byte("response")) {
						t.Fatalf("response = %q, error = %v", data, err)
					}
				}
				for round := 0; round < 2; round++ {
					if err := S.WriteHeaderWithReuse(client, "127.0.0.1", 80, version, true); err != nil {
						t.Fatal(err)
					}
					if responseFirst {
						readResponse()
					}
					if _, err := client.Write([]byte("request")); err != nil {
						t.Fatal(err)
					}
					if err := S.HalfClose(client); err != nil {
						t.Fatal(err)
					}
					if !responseFirst {
						readResponse()
					}
					if err := <-results; err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
}

func TestRequestCloseWriteReleasesStalledIO(t *testing.T) {
	for _, mode := range []string{"error", "zero", "active-write"} {
		t.Run(mode, func(t *testing.T) {
			run := func(t *testing.T) {
				raw, peer := net.Pipe()
				defer raw.Close()
				defer peer.Close()
				conn := &requestIOConn{Conn: raw, readStarted: make(chan struct{}), writeStarted: make(chan struct{}), forwardZero: true}
				request := &tcpRequestConn{Conn: conn, reader: bufio.NewReader(conn), reuse: true, replyWritten: mode != "error"}
				readDone := make(chan error, 1)
				go func() { _, err := request.Read(make([]byte, 1)); readDone <- err }()
				<-conn.readStarted
				writeDone := make(chan error, 1)
				if mode == "active-write" {
					go func() { _, err := request.Write([]byte("blocked")); writeDone <- err }()
					<-conn.writeStarted
				}
				closed := make(chan error, 1)
				go func() { closed <- request.CloseWrite() }()
				if mode != "active-write" {
					<-conn.writeStarted
				}
				finished := false
				select {
				case err := <-closed:
					finished = true
					if err == nil {
						t.Error("stalled CloseWrite succeeded")
					}
				case <-time.After(C.DefaultTCPTimeout + time.Second):
					t.Error("CloseWrite did not release stalled request I/O")
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
				_ = raw.Close()
				_ = peer.Close()
				if !finished {
					<-closed
				}
				if !readFinished {
					<-readDone
				}
				if mode == "active-write" {
					<-writeDone
				}
			}
			if mode == "active-write" {
				run(t)
			} else {
				synctest.Test(t, run)
			}
		})
	}
}

func TestRequestRelayReleasesStalledHalfClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		raw, peer := net.Pipe()
		upstream, upstreamPeer := net.Pipe()
		defer raw.Close()
		defer peer.Close()
		defer upstream.Close()
		_ = upstreamPeer.Close()
		conn := &requestIOConn{Conn: raw, readStarted: make(chan struct{}), writeStarted: make(chan struct{}), forwardZero: true}
		request := &tcpRequestConn{Conn: conn, reader: bufio.NewReader(conn), reuse: true, replyWritten: true}
		done := make(chan struct{})
		go func() { N.Relay(N.NewBufferedConn(request), upstream); close(done) }()
		<-conn.writeStarted
		finished := false
		select {
		case <-done:
			finished = true
		case <-time.After(C.DefaultTCPTimeout + time.Second):
			t.Error("Relay remained blocked after clean-copy CloseWrite")
		}
		_ = raw.Close()
		_ = peer.Close()
		if !finished {
			<-done
		}
	})
}
