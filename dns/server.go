package dns

import (
	"context"
	"net"
	"sync"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/sockopt"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	D "github.com/miekg/dns"
)

var (
	// Guards address and server: the app and the external controller both
	// replace the listener.
	serverMux sync.Mutex
	address   string
	server    = &Server{}

	dnsDefaultTTL uint32 = 600
)

type Server struct {
	service   atomic.TypedValue[resolver.Service]
	tcpServer *D.Server
	udpServer *D.Server
}

type serverHandler struct {
	*Server
	isUDP bool
}

// ServeDNS implement D.Handler ServeDNS
func (s serverHandler) ServeDNS(w D.ResponseWriter, r *D.Msg) {
	msg, err := s.service.Load().ServeMsg(context.Background(), r)
	if err != nil {
		m := new(D.Msg)
		m.SetRcode(r, D.RcodeServerFailure)
		// does not matter if this write fails
		w.WriteMsg(m)
		return
	}
	if s.isUDP {
		// RFC 6891: fit the reply into the client's advertised buffer size,
		// setting the TC bit if records must be dropped; 512 when no OPT present
		msg.Truncate(resolver.RequestUDPSize(r))
	}
	msg.Compress = true
	w.WriteMsg(msg)
}

func (s *Server) UDPHandler() D.Handler {
	return serverHandler{Server: s, isUDP: true}
}

func (s *Server) TCPHandler() D.Handler {
	return serverHandler{Server: s, isUDP: false}
}

func (s *Server) SetService(service resolver.Service) {
	s.service.Store(service)
}

func ReCreateServer(addr string, lc C.InboundListenConfig, service resolver.Service) {
	serverMux.Lock()
	defer serverMux.Unlock()
	if addr == address && service != nil {
		server.SetService(service)
		return
	}

	closeServerLocked()

	if addr == "" || lc == nil || service == nil {
		return
	}

	var err error
	defer func() {
		if err != nil {
			log.Errorln("Start DNS server error: %s", err.Error())
		}
	}()

	_, port, err := net.SplitHostPort(addr)
	if port == "0" || port == "" || err != nil {
		return
	}

	next := &Server{}
	next.SetService(service)
	server = next

	// Bind before returning so a later call always finds the sockets to close.
	p, udpErr := lc.ListenPacket(context.Background(), "udp", addr)
	if udpErr != nil {
		log.Errorln("Start DNS server(UDP) error: %s", udpErr.Error())
	} else {
		if err := sockopt.UDPReuseaddr(p); err != nil {
			log.Warnln("Failed to Reuse UDP Address: %s", err)
		}

		log.Infoln("DNS server(UDP) listening at: %s", p.LocalAddr().String())
		next.udpServer = &D.Server{Addr: addr, PacketConn: p, Handler: next.UDPHandler()}
		go func(udpServer *D.Server) { _ = udpServer.ActivateAndServe() }(next.udpServer)
	}

	l, tcpErr := lc.Listen(context.Background(), "tcp", addr)
	if tcpErr != nil {
		log.Errorln("Start DNS server(TCP) error: %s", tcpErr.Error())
	} else {
		log.Infoln("DNS server(TCP) listening at: %s", l.Addr().String())
		next.tcpServer = &D.Server{Addr: addr, Listener: l, Handler: next.TCPHandler()}
		go func(tcpServer *D.Server) { _ = tcpServer.ActivateAndServe() }(next.tcpServer)
	}

	// An address nothing serves would make the next call skip the retry.
	if next.udpServer != nil || next.tcpServer != nil {
		address = addr
	}
}

// ReplaceServerService hands a listener already serving addr the new service
// and closes one serving another address; it never opens a listener.
func ReplaceServerService(addr string, service resolver.Service) {
	serverMux.Lock()
	defer serverMux.Unlock()
	if address != "" && addr == address && service != nil {
		server.SetService(service)
		return
	}
	closeServerLocked()
}

// closeServerLocked frees the ports at once; queries in flight finish on the
// old service in the background instead of holding the caller.
func closeServerLocked() {
	for _, old := range []*D.Server{server.udpServer, server.tcpServer} {
		if old == nil {
			continue
		}
		if old.PacketConn != nil {
			_ = old.PacketConn.Close()
		}
		if old.Listener != nil {
			_ = old.Listener.Close()
		}
		// Shutdown also ends open TCP connections. It refuses a server whose
		// loop has not started, which the closed sockets end on their own.
		go func() { _ = old.Shutdown() }()
	}
	server = &Server{}
	address = ""
}
