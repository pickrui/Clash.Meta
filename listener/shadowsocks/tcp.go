package shadowsocks

import (
	"fmt"
	LR "github.com/metacubex/mihomo/listener/restls"
	"net"
	"strings"
	"sync/atomic"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/transport/shadowsocks/core"
	obfs "github.com/metacubex/mihomo/transport/simple-obfs"
	"github.com/metacubex/mihomo/transport/socks5"
)

type Listener struct {
	closed       atomic.Bool
	config       LC.ShadowsocksServer
	listeners    []net.Listener
	udpListeners []*UDPListener
	pickCipher   core.Cipher
	handler      *sing.ListenerHandler
	simpleObfs   func(net.Conn) net.Conn
	resTLS       *LR.Server
}

var _listener atomic.Pointer[Listener]

func New(config LC.ShadowsocksServer, tunnel C.Tunnel, additions ...inbound.Addition) (*Listener, error) {
	pickCipher, err := core.PickCipher(config.Cipher, nil, config.Password)
	if err != nil {
		return nil, err
	}

	h, err := sing.NewListenerHandler(sing.ListenerConfig{
		Tunnel:    tunnel,
		Type:      C.SHADOWSOCKS,
		Additions: additions,
		MuxOption: config.MuxOption,
	})
	if err != nil {
		return nil, err
	}

	sl := &Listener{config: config, pickCipher: pickCipher, handler: h}
	ready := false
	defer func() {
		if !ready {
			_ = sl.Close()
		}
	}()
	if config.ResTLS.Enable {
		sl.resTLS, err = LR.New(config.ResTLS, tunnel)
		if err != nil {
			return nil, err
		}
	}

	if config.SimpleObfs.Enable {
		switch config.SimpleObfs.Mode {
		case "http":
			sl.simpleObfs = obfs.NewHTTPObfsServer
		case "tls":
			sl.simpleObfs = obfs.NewTLSObfsServer
		default:
			return nil, fmt.Errorf("unsupported simple obfs mode: %s", config.SimpleObfs.Mode)
		}
	}

	for _, addr := range strings.Split(config.Listen, ",") {
		addr := addr

		if config.Udp {
			//UDP
			ul, err := NewUDP(addr, pickCipher, tunnel, additions...)
			if err != nil {
				return nil, err
			}
			sl.udpListeners = append(sl.udpListeners, ul)
		}

		//TCP
		l, err := inbound.Listen("tcp", addr)
		if err != nil {
			return nil, err
		}
		sl.listeners = append(sl.listeners, l)

		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					if sl.closed.Load() {
						break
					}
					continue
				}
				go sl.HandleConn(c, tunnel, additions...)
			}
		}()
	}

	ready = true
	_listener.Store(sl)
	return sl, nil
}

func (l *Listener) Close() error {
	if !l.closed.CompareAndSwap(false, true) {
		return nil
	}
	if l.resTLS != nil {
		l.resTLS.Close()
	}
	var retErr error
	for _, lis := range l.listeners {
		err := lis.Close()
		if err != nil {
			retErr = err
		}
	}
	for _, lis := range l.udpListeners {
		err := lis.Close()
		if err != nil {
			retErr = err
		}
	}
	return retErr
}

func (l *Listener) Config() string {
	return l.config.String()
}

func (l *Listener) AddrList() (addrList []net.Addr) {
	for _, lis := range l.listeners {
		addrList = append(addrList, lis.Addr())
	}
	for _, lis := range l.udpListeners {
		addrList = append(addrList, lis.LocalAddr())
	}
	return
}

func (l *Listener) HandleConn(conn net.Conn, tunnel C.Tunnel, additions ...inbound.Addition) {
	if l.closed.Load() {
		_ = conn.Close()
		return
	}
	if l.resTLS != nil {
		var err error
		conn, err = l.resTLS.WrapConn(conn)
		if err != nil {
			return
		}
	}
	if l.simpleObfs != nil {
		conn = l.simpleObfs(conn)
	}
	conn = l.pickCipher.StreamConn(conn)
	conn = N.NewDeadlineConn(conn) // embed ss can't handle readDeadline correctly

	target, err := socks5.ReadAddr0(conn)
	if err != nil {
		_ = conn.Close()
		return
	}
	l.handler.HandleSocket(target, conn, additions...)
	//tunnel.HandleTCPConn(inbound.NewSocket(target, conn, C.SHADOWSOCKS, additions...))
}

func HandleShadowSocks(conn net.Conn, tunnel C.Tunnel, additions ...inbound.Addition) bool {
	if listener := _listener.Load(); listener != nil && !listener.closed.Load() && listener.pickCipher != nil {
		go listener.HandleConn(conn, tunnel, additions...)
		return true
	}
	return false
}
