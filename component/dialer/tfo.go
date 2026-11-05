package dialer

import (
	"context"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/net/deadline"
	"github.com/metacubex/tfo-go"
)

var DisableTFO = false

type tfoConn struct {
	mu            sync.Mutex
	conn          net.Conn
	closed        bool
	dialOnce      sync.Once
	dialed        chan struct{}
	dialErr       error
	dialing       bool
	readDeadline  deadline.PipeDeadline
	readTime      time.Time
	writeTime     time.Time
	writeTimer    *time.Timer
	writeTimedOut bool
	cancel        context.CancelFunc
	ctx           context.Context
	dialFn        func(ctx context.Context, earlyData []byte) (net.Conn, error)
}

func (c *tfoConn) dial(earlyData []byte) {
	c.mu.Lock()
	if c.closed {
		c.dialErr = io.ErrClosedPipe
		close(c.dialed)
		c.mu.Unlock()
		return
	}
	c.dialing = true
	c.armWriteDeadline()
	c.mu.Unlock()

	conn, err := c.dialFn(c.ctx, earlyData)
	c.mu.Lock()
	c.dialing = false
	if c.writeTimer != nil {
		c.writeTimer.Stop()
	}
	if c.closed {
		err = io.ErrClosedPipe
	} else if c.writeTimedOut {
		err = os.ErrDeadlineExceeded
	}
	if err == nil {
		err = conn.SetReadDeadline(c.readTime)
		if err == nil {
			err = conn.SetWriteDeadline(c.writeTime)
		}
	}
	if err == nil {
		c.conn = conn
	}
	c.dialErr = err
	c.readDeadline.Set(time.Time{})
	close(c.dialed)
	c.cancel()
	c.mu.Unlock()
	if err != nil && conn != nil {
		_ = conn.Close()
	}
}

func (c *tfoConn) connection() (net.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, io.ErrClosedPipe
	}
	return c.conn, c.dialErr
}

func (c *tfoConn) Read(b []byte) (int, error) {
	conn, err := c.connection()
	if conn == nil && err == nil {
		select {
		case <-c.ctx.Done():
		case <-c.dialed:
		case <-c.readDeadline.Wait():
			return 0, os.ErrDeadlineExceeded
		}
		conn, err = c.connection()
		if conn == nil && err == nil {
			err = c.ctx.Err()
		}
	}
	if err != nil {
		return 0, err
	}
	return conn.Read(b)
}

func (c *tfoConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	expired := c.conn == nil && !c.writeTime.IsZero() && !time.Now().Before(c.writeTime)
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return 0, io.ErrClosedPipe
	}
	if expired {
		return 0, os.ErrDeadlineExceeded
	}
	firstWrite := false
	c.dialOnce.Do(func() {
		firstWrite = true
		c.dial(b)
	})
	conn, err := c.connection()
	if err != nil {
		return 0, err
	}
	if firstWrite {
		return len(b), nil
	}
	return conn.Write(b)
}

func (c *tfoConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.cancel()
	if c.writeTimer != nil {
		c.writeTimer.Stop()
	}
	c.readDeadline.Set(time.Time{})
	conn := c.conn
	c.mu.Unlock()
	if conn != nil {
		return conn.Close()
	}
	return nil
}

func (c *tfoConn) LocalAddr() net.Addr {
	if conn, _ := c.connection(); conn != nil {
		return conn.LocalAddr()
	}
	return &net.TCPAddr{}
}

func (c *tfoConn) RemoteAddr() net.Addr {
	if conn, _ := c.connection(); conn != nil {
		return conn.RemoteAddr()
	}
	return &net.TCPAddr{}
}

func (c *tfoConn) SetDeadline(t time.Time) error {
	return c.setDeadline(t, true, true)
}

func (c *tfoConn) SetReadDeadline(t time.Time) error {
	return c.setDeadline(t, true, false)
}

func (c *tfoConn) SetWriteDeadline(t time.Time) error {
	return c.setDeadline(t, false, true)
}

func (c *tfoConn) setDeadline(t time.Time, read, write bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return io.ErrClosedPipe
	}
	if read {
		c.readTime = t
		if c.conn == nil {
			c.readDeadline.Set(t)
		}
	}
	if write {
		c.writeTime = t
		c.armWriteDeadline()
	}
	if c.conn == nil {
		return nil
	}
	if read && write {
		return c.conn.SetDeadline(t)
	}
	if read {
		return c.conn.SetReadDeadline(t)
	}
	return c.conn.SetWriteDeadline(t)
}

// The handshake has no net.Conn yet, so its write deadline cancels the dial.
func (c *tfoConn) armWriteDeadline() {
	if c.writeTimer != nil {
		c.writeTimer.Stop()
	}
	if !c.dialing || c.writeTime.IsZero() {
		return
	}
	expires := c.writeTime
	c.writeTimer = time.AfterFunc(time.Until(expires), func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.dialing && c.writeTime == expires && !time.Now().Before(expires) {
			c.writeTimedOut = true
			c.cancel()
		}
	})
}

func (c *tfoConn) Upstream() any {
	conn, _ := c.connection()
	return conn
}

func (c *tfoConn) NeedAdditionalReadDeadline() bool {
	return false
}

func (c *tfoConn) NeedHandshake() bool {
	return c.Upstream() == nil
}

func (c *tfoConn) ReaderReplaceable() bool {
	return !c.NeedHandshake()
}

func (c *tfoConn) WriterReplaceable() bool {
	return !c.NeedHandshake()
}

func dialTFO(_ context.Context, netDialer net.Dialer, network, address string) (net.Conn, error) {
	// The caller may cancel its dial context once this lazy connection returns.
	ctx, cancel := context.WithTimeout(context.Background(), DefaultTCPTimeout)
	dialer := tfo.Dialer{Dialer: netDialer, DisableTFO: false}
	return &tfoConn{
		dialed:       make(chan struct{}),
		readDeadline: deadline.MakePipeDeadline(),
		cancel:       cancel,
		ctx:          ctx,
		dialFn: func(ctx context.Context, earlyData []byte) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address, earlyData)
		},
	}, nil
}
