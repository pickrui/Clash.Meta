package sing_shadowsocks

import (
	"context"
	"fmt"
	LR "github.com/metacubex/mihomo/listener/restls"
	"net"
	"strings"
	"sync/atomic"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/sockopt"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	embedSS "github.com/metacubex/mihomo/listener/shadowsocks"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/ntp"
	"github.com/metacubex/mihomo/transport/kcptun"
	obfs "github.com/metacubex/mihomo/transport/simple-obfs"

	shadowsocks "github.com/metacubex/sing-shadowsocks"
	"github.com/metacubex/sing-shadowsocks/shadowaead"
	"github.com/metacubex/sing-shadowsocks/shadowaead_2022"
	shadowtls "github.com/metacubex/sing-shadowtls"
	"github.com/metacubex/sing/common"
	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/network"
)

type Listener struct {
	closed       atomic.Bool
	config       LC.ShadowsocksServer
	listeners    []net.Listener
	udpListeners []net.PacketConn
	service      shadowsocks.Service
	shadowTLS    *shadowtls.Service
	simpleObfs   func(net.Conn) net.Conn
	resTLS       *LR.Server
}

var _listener atomic.Pointer[Listener]

// shadowTLSService is a wrapper for shadowsocks.Service to support shadowTLS.
type shadowTLSService struct {
	shadowsocks.Service
	shadowTLS *shadowtls.Service
}

func (s *shadowTLSService) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	if s.shadowTLS != nil {
		return s.shadowTLS.NewConnection(ctx, conn, metadata)
	}
	return s.Service.NewConnection(ctx, conn, metadata)
}

func New(config LC.ShadowsocksServer, tunnel C.Tunnel, additions ...inbound.Addition) (C.MultiAddrListener, error) {
	var sl *Listener
	isDefault := len(additions) == 0
	var err error
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-SHADOWSOCKS"),
			inbound.WithSpecialRules(""),
		}
	}

	udpTimeout := int64(sing.UDPTimeout.Seconds())

	h, err := sing.NewListenerHandler(sing.ListenerConfig{
		Tunnel:    tunnel,
		Type:      C.SHADOWSOCKS,
		Additions: additions,
		MuxOption: config.MuxOption,
	})
	if err != nil {
		return nil, err
	}

	sl = &Listener{}
	sl.config = config
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

	switch {
	case config.Cipher == shadowsocks.MethodNone:
		sl.service = shadowsocks.NewNoneService(udpTimeout, h)
	case common.Contains(shadowaead.List, config.Cipher):
		sl.service, err = shadowaead.NewService(config.Cipher, nil, config.Password, udpTimeout, h)
	case common.Contains(shadowaead_2022.List, config.Cipher):
		sl.service, err = shadowaead_2022.NewServiceWithPassword(config.Cipher, config.Password, udpTimeout, h, ntp.Now)
	default:
		err = fmt.Errorf("shadowsocks: unsupported method: %s", config.Cipher)
		return embedSS.New(config, tunnel, additions...)
	}
	if err != nil {
		return nil, err
	}

	if config.ShadowTLS.Enable {
		buildHandshake := func(handshake LC.ShadowTLSHandshakeOptions) (handshakeConfig shadowtls.HandshakeConfig) {
			handshakeConfig.Server = M.ParseSocksaddr(handshake.Dest)
			handshakeConfig.Dialer = sing.NewDialer(tunnel, handshake.Proxy)
			return
		}
		var handshakeForServerName map[string]shadowtls.HandshakeConfig
		if config.ShadowTLS.Version > 1 {
			handshakeForServerName = make(map[string]shadowtls.HandshakeConfig)
			for serverName, serverOptions := range config.ShadowTLS.HandshakeForServerName {
				handshakeForServerName[serverName] = buildHandshake(serverOptions)
			}
		}
		var wildcardSNI shadowtls.WildcardSNI
		switch config.ShadowTLS.WildcardSNI {
		case "authed":
			wildcardSNI = shadowtls.WildcardSNIAuthed
		case "all":
			wildcardSNI = shadowtls.WildcardSNIAll
		default:
			wildcardSNI = shadowtls.WildcardSNIOff
		}
		var shadowTLS *shadowtls.Service
		shadowTLS, err = shadowtls.NewService(shadowtls.ServiceConfig{
			Version:  config.ShadowTLS.Version,
			Password: config.ShadowTLS.Password,
			Users: common.Map(config.ShadowTLS.Users, func(it LC.ShadowTLSUser) shadowtls.User {
				return shadowtls.User{Name: it.Name, Password: it.Password}
			}),
			Handshake:              buildHandshake(config.ShadowTLS.Handshake),
			HandshakeForServerName: handshakeForServerName,
			StrictMode:             config.ShadowTLS.StrictMode,
			WildcardSNI:            wildcardSNI,
			Handler:                sl.service,
			Logger:                 log.SingLogger,
		})
		if err != nil {
			return nil, err
		}
		sl.service = &shadowTLSService{
			Service:   sl.service,
			shadowTLS: shadowTLS,
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

	var kcptunServer *kcptun.Server
	if config.KcpTun.Enable {
		kcptunServer = kcptun.NewServer(config.KcpTun.Config)
		config.Udp = true
	}

	for _, addr := range strings.Split(config.Listen, ",") {
		addr := addr

		if config.Udp {
			//UDP
			ul, err := inbound.ListenPacket("udp", addr)
			if err != nil {
				return nil, err
			}

			if err := sockopt.UDPReuseaddr(ul); err != nil {
				log.Warnln("Failed to Reuse UDP Address: %s", err)
			}

			sl.udpListeners = append(sl.udpListeners, ul)

			if kcptunServer != nil {
				go kcptunServer.Serve(ul, func(c net.Conn) {
					sl.HandleConn(c, tunnel)
				})

				continue // skip tcp listener
			}

			go func() {
				conn := bufio.NewPacketConn(ul)
				rwOptions := network.NewReadWaitOptions(conn, sl.service)
				readWaiter, isReadWaiter := bufio.CreatePacketReadWaiter(conn)
				if isReadWaiter {
					readWaiter.InitializeReadWaiter(rwOptions)
				}
				for {
					var (
						buff *buf.Buffer
						dest M.Socksaddr
						err  error
					)
					buff = nil // clear last loop status, avoid repeat release
					if isReadWaiter {
						buff, dest, err = readWaiter.WaitReadPacket()
					} else {
						buff = rwOptions.NewPacketBuffer()
						dest, err = conn.ReadPacket(buff)
						if buff != nil {
							rwOptions.PostReturn(buff)
						}
					}
					if err != nil {
						buff.Release()
						if sl.closed.Load() {
							break
						}
						continue
					}
					ctx := context.TODO()
					ctx = sing.WithInAddr(ctx, ul.LocalAddr())
					_ = sl.service.NewPacket(ctx, conn, buff, M.Metadata{
						Protocol: "shadowsocks",
						Source:   dest,
					})
				}
			}()
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

				go sl.HandleConn(c, tunnel)
			}
		}()
	}

	ready = true
	if isDefault {
		_listener.Store(sl)
	}
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
	ctx := sing.WithAdditions(context.TODO(), additions...)
	if l.simpleObfs != nil {
		conn = l.simpleObfs(conn)
	}
	err := l.service.NewConnection(ctx, conn, M.Metadata{
		Protocol: "shadowsocks",
		Source:   M.SocksaddrFromNet(conn.RemoteAddr()),
	})
	if err != nil {
		_ = conn.Close()
		return
	}
}

func HandleShadowSocks(conn net.Conn, tunnel C.Tunnel, additions ...inbound.Addition) bool {
	if listener := _listener.Load(); listener != nil && !listener.closed.Load() && listener.service != nil {
		go listener.HandleConn(conn, tunnel, additions...)
		return true
	}
	return embedSS.HandleShadowSocks(conn, tunnel, additions...)
}
