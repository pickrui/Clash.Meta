package kcptun

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/kcp-go"
	"github.com/metacubex/randv2"
	"github.com/metacubex/smux"
)

const Mode = "kcptun"

type DialFn func(ctx context.Context) (net.PacketConn, net.Addr, error)

type Client struct {
	once   sync.Once
	config Config
	block  kcp.BlockCrypt

	ctx    context.Context
	cancel context.CancelFunc

	muxes    []timedSession
	rr       int
	connMu   sync.Mutex
	sessions map[*smux.Session]time.Time
}

func NewClient(config Config) *Client {
	config.FillDefaults()
	block := config.NewBlock()

	ctx, cancel := context.WithCancel(context.Background())

	return &Client{
		config:   config,
		block:    block,
		ctx:      ctx,
		cancel:   cancel,
		muxes:    make([]timedSession, config.Conn),
		sessions: make(map[*smux.Session]time.Time),
	}
}

func (c *Client) Close() error {
	c.cancel()
	c.connMu.Lock()
	defer c.connMu.Unlock()
	for session := range c.sessions {
		_ = session.Close()
		delete(c.sessions, session)
	}
	clear(c.muxes)
	return nil
}

func (c *Client) createConn(ctx context.Context, dial DialFn) (*smux.Session, error) {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.ctx, cancel)
	defer stop()
	defer cancel()
	conn, addr, err := dial(ctx)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		_ = conn.Close()
		return nil, err
	}

	config := c.config
	convid := randv2.Uint32()
	kcpconn, err := kcp.NewConn4(convid, addr, c.block, config.DataShard, config.ParityShard, true, conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	kcpconn.SetStreamMode(true)
	kcpconn.SetWriteDelay(false)
	kcpconn.SetNoDelay(config.NoDelay, config.Interval, config.Resend, config.NoCongestion)
	kcpconn.SetWindowSize(config.SndWnd, config.RcvWnd)
	kcpconn.SetMtu(config.MTU)
	kcpconn.SetACKNoDelay(config.AckNodelay)
	kcpconn.SetRateLimit(uint32(config.RateLimit))

	_ = kcpconn.SetDSCP(config.DSCP)
	_ = kcpconn.SetReadBuffer(config.SockBuf)
	_ = kcpconn.SetWriteBuffer(config.SockBuf)
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = config.SmuxVer
	smuxConfig.MaxReceiveBuffer = config.SmuxBuf
	smuxConfig.MaxStreamBuffer = config.StreamBuf
	smuxConfig.MaxFrameSize = config.FrameSize
	smuxConfig.KeepAliveInterval = time.Duration(config.KeepAlive) * time.Second
	if smuxConfig.KeepAliveInterval >= smuxConfig.KeepAliveTimeout {
		smuxConfig.KeepAliveTimeout = 3 * smuxConfig.KeepAliveInterval
	}

	if err := smux.VerifyConfig(smuxConfig); err != nil {
		_ = kcpconn.Close()
		return nil, err
	}

	var netConn net.Conn = kcpconn
	if !config.NoComp {
		netConn = NewCompStream(netConn)
	}
	// stream multiplex
	return smux.Client(netConn, smuxConfig)
}

func (c *Client) OpenStream(ctx context.Context, dial DialFn) (*smux.Stream, error) {
	c.connMu.Lock()
	if err := c.ctx.Err(); err != nil {
		c.connMu.Unlock()
		return nil, net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		c.connMu.Unlock()
		return nil, err
	}
	c.once.Do(func() {
		if c.config.AutoExpire > 0 {
			go c.scavenge()
		}
	})
	idx := c.rr
	session := c.muxes[idx].session
	if session == nil || session.IsClosed() ||
		(c.config.AutoExpire > 0 && time.Now().After(c.muxes[idx].expiryDate)) {
		if session != nil && session.IsClosed() {
			delete(c.sessions, session)
		}
		var err error
		session, err = c.createConn(ctx, dial)
		if err != nil {
			c.connMu.Unlock()
			return nil, err
		}
		expires := time.Now().Add(time.Duration(c.config.AutoExpire) * time.Second)
		c.muxes[idx] = timedSession{session: session, expiryDate: expires}
		c.sessions[session] = expires.Add(time.Duration(c.config.ScavengeTTL) * time.Second)
	}
	c.rr = (idx + 1) % len(c.muxes)
	c.connMu.Unlock()
	return session.OpenStream()
}

// timedSession is a wrapper for smux.Session with expiry date
type timedSession struct {
	session    *smux.Session
	expiryDate time.Time
}

func (c *Client) scavenge() {
	ticker := time.NewTicker(scavengePeriod * time.Second)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			c.connMu.Lock()
			for session, expires := range c.sessions {
				if session.IsClosed() {
					delete(c.sessions, session)
				} else if now.After(expires) {
					_ = session.Close()
					delete(c.sessions, session)
					log.Debugln("scavenger: session closed due to ttl: %s", session.LocalAddr())
				}
			}
			c.connMu.Unlock()
		case <-c.ctx.Done():
			return
		}
	}
}
