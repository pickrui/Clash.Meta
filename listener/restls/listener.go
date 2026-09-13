package restls

import (
	"net"
	"runtime/debug"
	"sync"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/log"
)

// listener performs camouflage handshakes concurrently. A stalled peer must not
// prevent other clients from reaching the protocol's TCP or HTTP handler.
// The result channel stays open: shutdown must never race with a sender.
type listener struct {
	net.Listener
	server   *Server
	conns    chan net.Conn
	done     chan struct{}
	once     sync.Once
	err      error // published by closing done
	closeErr error
}

func NewListener(raw net.Listener, config LC.ResTLS, tunnel C.Tunnel) (net.Listener, error) {
	server, err := New(config, tunnel)
	if err != nil {
		return nil, err
	}
	l := &listener{Listener: raw, server: server, conns: make(chan net.Conn), done: make(chan struct{})}
	go l.run()
	return l, nil
}

func (l *listener) run() {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			l.stop(err)
			return
		}
		go l.handshake(conn)
	}
}

func (l *listener) handshake(raw net.Conn) {
	defer func() {
		if value := recover(); value != nil {
			_ = raw.Close()
			log.Errorln("restls server panic: %v\n%s", value, debug.Stack())
		}
	}()
	conn, err := l.server.WrapConn(raw)
	if err != nil {
		return
	}
	select {
	case l.conns <- conn:
	case <-l.done:
		_ = conn.Close()
	}
}

func (l *listener) Accept() (net.Conn, error) {
	select {
	case <-l.done:
		return nil, l.err
	default:
	}
	select {
	case conn := <-l.conns:
		select {
		case <-l.done:
			_ = conn.Close()
			return nil, l.err
		default:
			return conn, nil
		}
	case <-l.done:
		return nil, l.err
	}
}

func (l *listener) stop(err error) {
	l.once.Do(func() {
		l.err = err
		l.server.Close()
		l.closeErr = l.Listener.Close()
		close(l.done)
	})
}

func (l *listener) Close() error {
	l.stop(net.ErrClosed)
	return l.closeErr
}
