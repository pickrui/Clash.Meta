package snell

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/shadowsocks/shadowaead"
)

func TestPoolConnCloseIsIdempotent(t *testing.T) {
	rawConn := &recordingConn{}
	pooledConn := &Snell{Conn: rawConn}
	factoryConn := &Snell{Conn: &recordingConn{}}
	pool := NewPool(func(context.Context) (*Snell, error) {
		return factoryConn, nil
	})
	conn := &PoolConn{Snell: pooledConn, pool: pool}

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	if rawConn.writes != 0 || !rawConn.closed {
		t.Fatal("unused connection should close without pooling")
	}

	got, err := pool.pool.Get()
	if err != nil {
		t.Fatal(err)
	}
	if got.conn != factoryConn || got.conn == pooledConn {
		t.Fatal("closed connection was returned to the pool")
	}
}

func TestPoolConnCloseWriteDoesNotReturnConnectionToPool(t *testing.T) {
	rawConn := &recordingConn{readErr: shadowaead.ErrZeroChunk}
	pooledConn := &Snell{Conn: rawConn, reply: true}
	factoryConn := &Snell{Conn: &recordingConn{}}
	pool := NewPool(func(context.Context) (*Snell, error) {
		return factoryConn, nil
	})
	conn := &PoolConn{Snell: pooledConn, pool: pool}
	if _, err := conn.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	conn.MarkReusable()

	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}

	got, err := pool.pool.Get()
	if err != nil {
		t.Fatal(err)
	}
	if got.conn != factoryConn {
		t.Fatal("CloseWrite should not put the active connection back into the pool")
	}
	if rawConn.writes != 2 {
		t.Fatalf("request and CloseWrite should produce two writes, got %d", rawConn.writes)
	}
	if !pooledConn.reply {
		t.Fatal("CloseWrite should not reset reply while the read side may still be active")
	}
	if _, err = conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("expected peer half-close before pooling, got %v", err)
	}

	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
	got, err = pool.pool.Get()
	if err != nil {
		t.Fatal(err)
	}
	if got.conn != pooledConn {
		t.Fatal("Close should return the connection to the pool after CloseWrite")
	}
	if rawConn.writes != 2 {
		t.Fatalf("Close after CloseWrite should not write again, got %d", rawConn.writes)
	}
	if pooledConn.reply {
		t.Fatal("Close should reset reply before returning the connection to the pool")
	}
}

func TestPoolConnCloseWithoutPeerHalfCloseClosesRawConnection(t *testing.T) {
	rawConn := &recordingConn{}
	pooledConn := &Snell{Conn: rawConn}
	factoryConn := &Snell{Conn: &recordingConn{}}
	pool := NewPool(func(context.Context) (*Snell, error) {
		return factoryConn, nil
	})
	conn := &PoolConn{Snell: pooledConn, pool: pool}

	if _, err := conn.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	conn.MarkReusable()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	if !rawConn.closed {
		t.Fatal("connection without peer half-close should close the raw connection")
	}
	got, err := pool.pool.Get()
	if err != nil {
		t.Fatal(err)
	}
	if got.conn != factoryConn {
		t.Fatal("connection without peer half-close should not return to the pool")
	}
}

func TestPoolConnReadZeroChunkReturnsEOF(t *testing.T) {
	conn := &PoolConn{Snell: &Snell{Conn: zeroChunkConn{}, reply: true}}

	n, err := conn.Read(make([]byte, 1))
	if n != 0 {
		t.Fatalf("read length mismatch: %d", n)
	}
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF for zero chunk, got %v", err)
	}
}

type recordingConn struct {
	writes  int
	readErr error
	closed  bool
}

func (c *recordingConn) Read([]byte) (int, error) {
	if c.readErr != nil {
		return 0, c.readErr
	}
	return 0, io.EOF
}

func (c *recordingConn) Write(b []byte) (int, error) {
	c.writes++
	return len(b), nil
}

func (c *recordingConn) Close() error {
	c.closed = true
	return nil
}

func (*recordingConn) LocalAddr() net.Addr {
	return recordingAddr("local")
}

func (*recordingConn) RemoteAddr() net.Addr {
	return recordingAddr("remote")
}

func (*recordingConn) SetDeadline(time.Time) error {
	return nil
}

func (*recordingConn) SetReadDeadline(time.Time) error {
	return nil
}

func (*recordingConn) SetWriteDeadline(time.Time) error {
	return nil
}

type recordingAddr string

func (a recordingAddr) Network() string {
	return string(a)
}

func (a recordingAddr) String() string {
	return string(a)
}

type zeroChunkConn struct{}

func (zeroChunkConn) Read([]byte) (int, error) {
	return 0, shadowaead.ErrZeroChunk
}

func (zeroChunkConn) Write(b []byte) (int, error) {
	return len(b), nil
}

func (zeroChunkConn) Close() error {
	return nil
}

func (zeroChunkConn) LocalAddr() net.Addr {
	return recordingAddr("local")
}

func (zeroChunkConn) RemoteAddr() net.Addr {
	return recordingAddr("remote")
}

func (zeroChunkConn) SetDeadline(time.Time) error {
	return nil
}

func (zeroChunkConn) SetReadDeadline(time.Time) error {
	return nil
}

func (zeroChunkConn) SetWriteDeadline(time.Time) error {
	return nil
}
