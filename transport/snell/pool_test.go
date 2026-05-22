package snell

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/shadowsocks/shadowaead"
)

func TestPoolConnReusesAfterBothSidesHalfClosed(t *testing.T) {
	var connections atomic.Int32
	errCh := make(chan error, 1)

	pool := newReuseTestPool(t, &connections, func(serverConn net.Conn) {
		serverSnell := StreamConn(serverConn, []byte("password"), Version4)
		serverSnell.reply = true
		go serveReuseTestConn(serverSnell, 2, errCh)
	})

	for i := 0; i < 2; i++ {
		conn, err := pool.Get()
		if err != nil {
			t.Fatal(err)
		}

		if err := WriteHeaderWithReuse(conn, "example.com", 80, Version4, true); err != nil {
			t.Fatal(err)
		}
		if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
			fatalWithServerError(t, errCh, err)
		}

		data, err := io.ReadAll(conn)
		if err != nil {
			fatalWithServerError(t, errCh, err)
		}
		if string(data) != fmt.Sprintf("response-%d", i) {
			t.Fatalf("unexpected response: %q", data)
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
	}

	if count := connections.Load(); count != 1 {
		t.Fatalf("expected one pooled connection, got %d", count)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not finish")
	}
}

func TestPoolConnClosesBeforeServerHalfClose(t *testing.T) {
	var connections atomic.Int32
	releaseResponse := make(chan struct{})
	errCh := make(chan error, 2)

	pool := newReuseTestPool(t, &connections, func(serverConn net.Conn) {
		serverSnell := StreamConn(serverConn, []byte("password"), Version4)
		serverSnell.reply = true
		go serveDelayedResponseConn(serverSnell, releaseResponse, errCh)
	})

	conn, err := pool.Get()
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteHeaderWithReuse(conn, "example.com", 80, Version4, true); err != nil {
		t.Fatal(err)
	}
	if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		fatalWithServerError(t, errCh, err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	secondConn, err := pool.Get()
	if err != nil {
		t.Fatal(err)
	}
	_ = secondConn.Close()
	close(releaseResponse)

	if count := connections.Load(); count != 2 {
		t.Fatalf("expected premature close to discard connection, got %d connections", count)
	}
}

func fatalWithServerError(t *testing.T, errCh <-chan error, err error) {
	t.Helper()
	select {
	case serverErr := <-errCh:
		t.Fatalf("%v; server error: %v", err, serverErr)
	default:
		t.Fatal(err)
	}
}

func newReuseTestPool(t *testing.T, connections *atomic.Int32, serve func(net.Conn)) *Pool {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			serve(conn)
		}
	}()

	return NewPool(func(ctx context.Context) (*Snell, error) {
		connections.Add(1)
		var dialer net.Dialer
		conn, err := dialer.DialContext(ctx, "tcp", listener.Addr().String())
		if err != nil {
			return nil, err
		}
		return StreamConn(conn, []byte("password"), Version4), nil
	})
}

func serveReuseTestConn(conn *Snell, requests int, errCh chan<- error) {
	defer conn.Close()
	for i := 0; i < requests; i++ {
		if err := readReuseTestRequest(conn); err != nil {
			errCh <- err
			return
		}
		if _, err := conn.Write([]byte{CommandTunnel}); err != nil {
			errCh <- err
			return
		}
		if err := readReuseTestHalfClose(conn); err != nil {
			errCh <- err
			return
		}
		if _, err := conn.Write([]byte(fmt.Sprintf("response-%d", i))); err != nil {
			errCh <- err
			return
		}
		if _, err := conn.Write(endSignal); err != nil {
			errCh <- err
			return
		}
	}
	errCh <- nil
}

func serveDelayedResponseConn(conn *Snell, release <-chan struct{}, errCh chan<- error) {
	defer conn.Close()
	if err := readReuseTestRequest(conn); err != nil {
		errCh <- err
		return
	}
	if _, err := conn.Write([]byte{CommandTunnel}); err != nil {
		errCh <- err
		return
	}
	if err := readReuseTestHalfClose(conn); err != nil {
		errCh <- err
		return
	}
	<-release
	_, _ = conn.Write([]byte("late response"))
	_, _ = conn.Write(endSignal)
}

func readReuseTestRequest(conn *Snell) error {
	var fixed [3]byte
	if _, err := io.ReadFull(conn, fixed[:]); err != nil {
		return err
	}
	if fixed[0] != Version {
		return fmt.Errorf("unexpected version: %d", fixed[0])
	}
	if fixed[1] != CommandConnectV2 {
		return fmt.Errorf("unexpected command: %d", fixed[1])
	}
	if fixed[2] > 0 {
		if _, err := io.CopyN(io.Discard, conn, int64(fixed[2])); err != nil {
			return err
		}
	}

	var hostLen [1]byte
	if _, err := io.ReadFull(conn, hostLen[:]); err != nil {
		return err
	}
	if _, err := io.CopyN(io.Discard, conn, int64(hostLen[0])); err != nil {
		return err
	}

	var port [2]byte
	if _, err := io.ReadFull(conn, port[:]); err != nil {
		return err
	}
	if binary.BigEndian.Uint16(port[:]) != 80 {
		return fmt.Errorf("unexpected port: %d", binary.BigEndian.Uint16(port[:]))
	}
	return nil
}

func readReuseTestHalfClose(conn *Snell) error {
	var b [1]byte
	_, err := conn.Read(b[:])
	if !errors.Is(err, shadowaead.ErrZeroChunk) {
		return fmt.Errorf("expected zero chunk, got %v", err)
	}
	return nil
}
