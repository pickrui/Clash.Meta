package restls

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/inner"
	"github.com/metacubex/mihomo/transport/restls"
)

// Server owns handshakes and unauthenticated fallback relays until the
// authenticated connection is transferred to the protocol handler.
type Server struct {
	config  restls.ServerConfig
	mu      sync.Mutex
	closed  bool
	pending map[*attempt]struct{}
}

type attempt struct{ cancel context.CancelFunc }

func Validate(config LC.ResTLS) error {
	if strings.TrimSpace(config.Dest) == "" {
		return fmt.Errorf("restls: missing camouflage destination")
	}
	// Use the protocol parser so client and server accept the same scripts.
	if _, err := restls.NewRestlsConfig(config.Dest, config.Password, "tls13", config.RestlsScript, "chrome"); err != nil {
		return fmt.Errorf("restls: %w", err)
	}
	return nil
}

func New(config LC.ResTLS, tunnel C.Tunnel) (*Server, error) {
	if err := Validate(config); err != nil {
		return nil, err
	}
	return &Server{pending: make(map[*attempt]struct{}), config: restls.ServerConfig{
		ServerHostname: config.Dest, Password: config.Password, RestlsScript: config.RestlsScript,
		MinRecordLen: config.MinRecordLen, RateLimit: config.RateLimit,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return inner.HandleTcp(tunnel, address, config.Proxy)
		},
	}}, nil
}

func (s *Server) WrapConn(conn net.Conn) (result net.Conn, err error) {
	ctx, cancel := context.WithCancel(context.Background())
	a := &attempt{cancel: cancel}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		cancel()
		_ = conn.Close()
		return nil, net.ErrClosed
	}
	s.pending[a] = struct{}{}
	s.mu.Unlock()
	stopInbound := context.AfterFunc(ctx, func() { _ = conn.Close() })
	var stopTarget func() bool
	defer func() {
		s.mu.Lock()
		delete(s.pending, a)
		closed := s.closed
		// Removing the attempt transfers ownership before Close can cancel it.
		stopInbound()
		if stopTarget != nil {
			stopTarget()
		}
		s.mu.Unlock()
		if closed && result != nil {
			_ = result.Close()
			result = nil
			err = net.ErrClosed
		}
		if result == nil {
			cancel()
			_ = conn.Close()
		} else {
			result = &sessionConn{Conn: result, cancel: cancel}
		}
	}()
	config := s.config
	config.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		target, err := s.config.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		// Restls performs blocking reads on both sockets; cancelling a context
		// alone cannot release a stalled camouflage target or fallback relay.
		stopTarget = context.AfterFunc(ctx, func() { _ = target.Close() })
		return target, nil
	}
	return restls.Server(ctx, conn, &config)
}

func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for a := range s.pending {
		a.cancel()
	}
}

// The authenticated session keeps the Restls context alive after handoff.
type sessionConn struct {
	net.Conn
	cancel context.CancelFunc
}

func (c *sessionConn) Close() error {
	c.cancel()
	return c.Conn.Close()
}

func (c *sessionConn) Upstream() any { return c.Conn }
