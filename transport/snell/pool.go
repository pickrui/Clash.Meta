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
	maxUsesPerConn int
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
}

func (p *Pool) Get() (net.Conn, error) {
	return p.GetContext(context.Background())
}

func (p *Pool) GetContext(ctx context.Context) (net.Conn, error) {
	entry, err := p.pool.GetContext(ctx)
	if err != nil {
		return nil, err
	}

	entry.uses++
	return &PoolConn{Snell: entry.conn, pool: p, uses: entry.uses}, nil
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
	p.pool.Put(&pooledEntry{conn: conn, uses: uses})
}

type PoolConn struct {
	*Snell
	pool           *Pool
	uses           int
	closeWriteOnce sync.Once
	closeWriteErr  error
	requestStarted atomic.Bool
	reusableState  atomic.Int32
	closeOnce      sync.Once
	closeErr       error
}

func (pc *PoolConn) Read(b []byte) (int, error) {
	n, err := pc.Snell.Read(b)
	if err == shadowaead.ErrZeroChunk {
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

		// mihomo use SetReadDeadline to break bidirectional copy between client and server.
		// reset it before reuse connection to avoid io timeout error.
		_ = pc.Snell.Conn.SetReadDeadline(time.Time{})
		pc.Snell.reply = false
		pc.pool.put(pc.Snell, pc.uses)
	})
	return pc.closeErr
}

func NewPool(factory func(context.Context) (*Snell, error)) *Pool {
	p := &Pool{maxUsesPerConn: defaultMaxUsesPerConn}
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
