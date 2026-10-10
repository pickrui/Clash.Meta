package snell

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/component/pool"
	"github.com/metacubex/mihomo/transport/shadowsocks/shadowaead"
)

type Pool struct {
	pool           *pool.Pool[*pooledEntry]
	factory        func(context.Context) (*Snell, error)
	maxUsesPerConn int
}

func (p *Pool) Warm(ctx context.Context, count int) {
	for range count {
		conn, err := p.factory(ctx)
		if err != nil {
			return
		}
		p.put(conn, 0)
	}
}

const (
	poolConnNew int32 = iota
	poolConnReusable
	poolConnClosedBeforeReuse

	defaultMaxUsesPerConn = 2
)

type pooledEntry struct {
	conn *Snell
	uses int
	// idle watches a connection that waited in the pool; nil for one the
	// factory dialed for this request.
	idle *idleConn
}

func (p *Pool) Get() (net.Conn, error) {
	return p.GetContext(context.Background())
}

func (p *Pool) GetContext(ctx context.Context) (net.Conn, error) {
	for {
		// A canceled request closes the connection it takes before using it.
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		entry, err := p.pool.GetContext(ctx)
		if err != nil {
			return nil, err
		}
		if entry.idle != nil && !entry.idle.claim() {
			// The server closed it while it waited; the watch already closed it.
			_ = entry.conn.Close()
			continue
		}

		entry.uses++
		return &PoolConn{Snell: entry.conn, pool: p, uses: entry.uses, reused: entry.idle != nil}, nil
	}
}

// Dial opens a connection for one request without taking an idle one.
func (p *Pool) Dial(ctx context.Context) (*PoolConn, error) {
	conn, err := p.factory(ctx)
	if err != nil {
		return nil, err
	}
	return &PoolConn{Snell: conn, pool: p, uses: 1}, nil
}

func (p *Pool) Put(conn *Snell) {
	if err := HalfClose(conn); err != nil {
		_ = conn.Close()
		return
	}

	p.put(conn, 0)
}

func (p *Pool) put(conn *Snell, uses int) {
	if p.maxUsesPerConn > 0 && uses >= p.maxUsesPerConn {
		_ = conn.Close()
		return
	}
	idle, ok := conn.Conn.(*idleConn)
	if !ok {
		idle = &idleConn{Conn: conn.Conn}
		conn.Conn = idle
	}
	idle.park()
	p.pool.Put(&pooledEntry{conn: conn, uses: uses, idle: idle})
}

func (p *Pool) Close() error {
	return p.pool.Close()
}

type PoolConn struct {
	*Snell
	pool           *Pool
	uses           int
	reused         bool
	closeWriteOnce sync.Once
	closeWriteErr  error
	requestStarted atomic.Bool
	reusableState  atomic.Int32
	peerClosed     atomic.Bool
	closeOnce      sync.Once
	closeErr       error
}

func (pc *PoolConn) Read(b []byte) (int, error) {
	n, err := pc.Snell.Read(b)
	if err == shadowaead.ErrZeroChunk {
		pc.peerClosed.Store(true)
		return n, io.EOF
	}
	return n, err
}

func (pc *PoolConn) Write(b []byte) (int, error) {
	n, err := pc.Snell.Write(b)
	if err == nil && n == len(b) && len(b) > 0 {
		pc.requestStarted.Store(true)
	}
	return n, err
}

// Reused reports whether the connection waited idle in the pool before this
// request, rather than being dialed for it.
func (pc *PoolConn) Reused() bool {
	return pc.reused
}

func (pc *PoolConn) MarkReusable() {
	if pc.requestStarted.Load() {
		pc.reusableState.CompareAndSwap(poolConnNew, poolConnReusable)
	}
}

func (pc *PoolConn) CloseWrite() error {
	pc.closeWriteOnce.Do(func() {
		if pc.reusableState.Load() != poolConnReusable {
			pc.reusableState.CompareAndSwap(poolConnNew, poolConnClosedBeforeReuse)
			pc.closeWriteErr = pc.Snell.Close()
			return
		}
		pc.closeWriteErr = writeZeroChunk(pc.Snell)
	})
	return pc.closeWriteErr
}

func (pc *PoolConn) Close() error {
	pc.closeOnce.Do(func() {
		if pc.reusableState.Load() != poolConnReusable {
			pc.closeErr = pc.CloseWrite()
			return
		}

		if err := pc.CloseWrite(); err != nil {
			pc.closeErr = err
			_ = pc.Snell.Close()
			return
		}
		if !pc.peerClosed.Load() {
			_ = pc.Snell.Close()
			return
		}

		// mihomo use SetReadDeadline to break bidirectional copy between client and server.
		// reset it before reuse connection to avoid io timeout error.
		_ = pc.Snell.Conn.SetReadDeadline(time.Time{})
		pc.Snell.reply = false
		pc.Snell.answered.Store(false)
		pc.pool.put(pc.Snell, pc.uses)
	})
	return pc.closeErr
}

func NewPool(factory func(context.Context) (*Snell, error)) *Pool {
	p := &Pool{factory: factory, maxUsesPerConn: defaultMaxUsesPerConn}
	p.pool = pool.New[*pooledEntry](
		func(ctx context.Context) (*pooledEntry, error) {
			conn, err := factory(ctx)
			if err != nil {
				return nil, err
			}
			return &pooledEntry{conn: conn}, nil
		},
		pool.WithAge[*pooledEntry](15000),
		pool.WithSize[*pooledEntry](10),
		pool.WithEvict[*pooledEntry](func(item *pooledEntry) {
			_ = item.conn.Close()
		}),
	)

	return p
}

// idleConn keeps one Read in flight on a pooled connection, as net/http's
// persistConn does. A server that closes the connection while it waits in the
// pool (restart, drain, idle timeout) is noticed at once instead of failing the
// next request, and once the connection is taken that same Read serves the
// reply. Nothing is in flight on an idle connection, so any byte, EOF or error
// read while idle ends it.
type idleConn struct {
	net.Conn
	mu      sync.Mutex
	idle    bool
	dead    bool
	pending chan struct{} // closed when the parked Read returns; nil when none is in flight
	parked  []byte        // what the parked Read got, served by the next Read
	err     error
}

func (c *idleConn) park() {
	c.mu.Lock()
	if c.dead || c.pending != nil || len(c.parked) > 0 || c.err != nil {
		// A connection with an unread result cannot be idle.
		c.dead = true
		c.mu.Unlock()
		_ = c.Conn.Close()
		return
	}
	c.idle = true
	done := make(chan struct{})
	c.pending = done
	c.mu.Unlock()

	go func() {
		buf := make([]byte, 1)
		n, err := c.Conn.Read(buf)
		c.mu.Lock()
		c.pending = nil
		idle := c.idle
		if idle {
			c.dead = true
		} else {
			c.parked = buf[:n]
			c.err = err
		}
		c.mu.Unlock()
		close(done)
		if idle {
			_ = c.Conn.Close()
		}
	}()
}

// claim takes the connection out of the pool; false once it closed while idle.
func (c *idleConn) claim() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dead {
		return false
	}
	c.idle = false
	return true
}

func (c *idleConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	done := c.pending
	c.mu.Unlock()
	if done != nil {
		<-done
	}

	c.mu.Lock()
	if len(c.parked) > 0 || c.err != nil {
		n := copy(b, c.parked)
		c.parked = c.parked[n:]
		var err error
		if len(c.parked) == 0 {
			err, c.err = c.err, nil
		}
		c.mu.Unlock()
		return n, err
	}
	c.mu.Unlock()
	return c.Conn.Read(b)
}
