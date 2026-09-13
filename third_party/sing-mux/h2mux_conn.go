package mux

import (
	"context"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/metacubex/sing/common"
	"github.com/metacubex/sing/common/baderror"
	M "github.com/metacubex/sing/common/metadata"
)

type httpConn struct {
	reader    io.ReadCloser
	writer    io.Writer
	setupOnce sync.Once
	create    chan struct{}
	err       error
	cancel    context.CancelFunc
}

func newHTTPConn(reader io.ReadCloser, writer io.Writer) *httpConn {
	conn := newLateHTTPConn(writer, nil)
	conn.setup(reader, nil)
	return conn
}

func newLateHTTPConn(writer io.Writer, cancel context.CancelFunc) *httpConn {
	return &httpConn{
		create: make(chan struct{}),
		writer: writer,
		cancel: cancel,
	}
}

func (c *httpConn) setup(reader io.ReadCloser, err error) {
	c.setupOnce.Do(func() {
		c.reader = reader
		c.err = err
		close(c.create)
	})
	if c.err != nil && reader != nil { // conn already closed before setup
		_ = reader.Close()
	}
}

func (c *httpConn) Read(b []byte) (n int, err error) {
	<-c.create
	if c.reader == nil {
		return 0, c.err
	}
	n, err = c.reader.Read(b)
	return n, baderror.WrapH2(err)
}

func (c *httpConn) Write(b []byte) (n int, err error) {
	n, err = c.writer.Write(b)
	return n, baderror.WrapH2(err)
}

func (c *httpConn) Close() error {
	c.setup(nil, net.ErrClosed)
	if c.cancel != nil {
		c.cancel()
	}
	return common.Close(c.reader, c.writer)
}

func (c *httpConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *httpConn) RemoteAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *httpConn) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *httpConn) SetReadDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *httpConn) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *httpConn) NeedAdditionalReadDeadline() bool {
	return true
}
