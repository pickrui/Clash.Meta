package net

import (
	"context"
	"net"
	"sync"
)

type handleContextListener struct {
	net.Listener
	ctx       context.Context
	cancel    context.CancelFunc
	conns     chan net.Conn
	done      chan struct{}
	initOnce  sync.Once
	closeOnce sync.Once
	err       error // published by closing done
	closeErr  error
	handle    func(context.Context, net.Conn) (net.Conn, error)
	panicLog  func(any)
}

func (l *handleContextListener) init() {
	go func() {
		for {
			c, err := l.Listener.Accept()
			if err != nil {
				l.stop(err)
				return
			}
			go l.handshake(c)
		}
	}()
}

func (l *handleContextListener) handshake(raw net.Conn) {
	// Listener cancellation owns the handshake, not an already accepted
	// application connection. Detach that cancellation at handoff.
	ctx, cancel := context.WithCancel(context.WithoutCancel(l.ctx))
	stopParent := context.AfterFunc(l.ctx, cancel)
	stopRaw := context.AfterFunc(ctx, func() { _ = raw.Close() })
	var result net.Conn
	handedOff := false
	defer func() {
		stopParent()
		stopRaw()
		if !handedOff {
			cancel()
			_ = raw.Close()
			if result != nil {
				_ = result.Close()
			}
		}
		if v := recover(); v != nil && l.panicLog != nil {
			l.panicLog(v)
		}
	}()
	if l.ctx.Err() != nil {
		return
	}
	var err error
	result, err = l.handle(ctx, raw)
	if err != nil || result == nil {
		return
	}
	// A cancellation callback that already started may not have called
	// cancel/Close yet. Never hand off a connection in that race.
	if !stopParent() || !stopRaw() {
		return
	}
	if ctx.Err() != nil || l.ctx.Err() != nil {
		return
	}
	owned := &handleListenerConn{Conn: result, cancel: cancel}
	// conns is never closed: a late handshake cannot panic while publishing.
	select {
	case l.conns <- owned:
		handedOff = true
	case <-l.done:
	}
}

func (l *handleContextListener) Accept() (net.Conn, error) {
	l.initOnce.Do(l.init)
	select {
	case <-l.done:
		return nil, l.err
	default:
	}
	select {
	case c := <-l.conns:
		select {
		case <-l.done:
			_ = c.Close()
			return nil, l.err
		default:
			return c, nil
		}
	case <-l.done:
		return nil, l.err
	}
}

func (l *handleContextListener) stop(err error) {
	l.closeOnce.Do(func() {
		l.err = err
		close(l.done)
		l.cancel()
		l.closeErr = l.Listener.Close()
	})
}
func (l *handleContextListener) Close() error { l.stop(net.ErrClosed); return l.closeErr }

type handleListenerConn struct {
	net.Conn
	cancel context.CancelFunc
}

func (c *handleListenerConn) Close() error  { c.cancel(); return c.Conn.Close() }
func (c *handleListenerConn) Upstream() any { return c.Conn }

// I/O has no buffering here; TLS-aware protocols may inspect the wrapped stream.
func (c *handleListenerConn) ReaderReplaceable() bool { return true }
func (c *handleListenerConn) WriterReplaceable() bool { return true }

func NewHandleContextListener(ctx context.Context, l net.Listener, handle func(context.Context, net.Conn) (net.Conn, error), panicLog func(any)) net.Listener {
	ctx, cancel := context.WithCancel(ctx)
	result := &handleContextListener{Listener: l, ctx: ctx, cancel: cancel, conns: make(chan net.Conn), done: make(chan struct{}), handle: handle, panicLog: panicLog}
	context.AfterFunc(ctx, func() { _ = result.Close() })
	return result
}
