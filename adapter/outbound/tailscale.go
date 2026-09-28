//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/iface/anet"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/tailnet"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/log"

	ts "github.com/metacubex/tailscale"
	"github.com/metacubex/tailscale/envknob"
	"github.com/metacubex/tailscale/hostinfo"
	"github.com/metacubex/tailscale/ipn"
	"github.com/metacubex/tailscale/ipn/ipnstate"
	"github.com/metacubex/tailscale/net/netmon"
	"github.com/metacubex/tailscale/tailcfg"
	"github.com/metacubex/tailscale/tsnet"
	D "github.com/miekg/dns"
	"github.com/samber/lo"
)

type Tailscale struct {
	*Base
	dnsResolver  *dns.Resolver
	dnsTransport tailscaleDNSTransport
	option       TailscaleOption
	sessionKey   string
	seq          uint64
	ctx          context.Context
	cancel       context.CancelFunc

	mu      sync.Mutex
	session *tailscaleSession
	closed  bool
	// unregister removes the routes and DNS client published for session.
	unregister func()
}

type TailscaleOption struct {
	BasicOption
	Name       string `proxy:"name"`
	Hostname   string `proxy:"hostname,omitempty"`
	AuthKey    string `proxy:"auth-key,omitempty"`
	ControlURL string `proxy:"control-url,omitempty"`
	StateDir   string `proxy:"state-dir,omitempty"`
	Ephemeral  bool   `proxy:"ephemeral,omitempty"`
	UDP        bool   `proxy:"udp,omitempty"`

	AcceptRoutes           *bool  `proxy:"accept-routes,omitempty"`
	ExitNode               string `proxy:"exit-node,omitempty"`
	ExitNodeAllowLANAccess *bool  `proxy:"exit-node-allow-lan-access,omitempty"`
}

func init() {
	hostinfo.RegisterHostinfoNewHook(func(hi *tailcfg.Hostinfo) {
		versionDotTxt := strings.TrimSpace(ts.VersionDotTxt)
		hi.IPNVersion = fmt.Sprintf("%s-%s-%s", versionDotTxt, C.MihomoName, C.Version)
	})
	envknob.SetNoLogsNoSupport()
	if runtime.GOOS == "android" { // Android SDK 30 no longer permits Go's net.Interfaces to work (Issue 2293)
		netmon.RegisterInterfaceGetter(func() (nif []netmon.Interface, err error) {
			log.Debugln("[Tailscale] InterfaceGetter: start, IsForceAnet: %v", anet.IsForceAnet())
			ifaces, err := anet.Interfaces()
			if err != nil {
				log.Warnln("[Tailscale] anet.Interfaces failed: %v", err)
				return nil, err
			}
			for _, iff := range ifaces {
				addrs, err := anet.InterfaceAddrsByInterface(&iff)
				if err != nil {
					log.Warnln("[Tailscale] anet.InterfaceAddrsByInterface(%v) failed: %v", iff.Name, err)
					continue
				}
				nif = append(nif, netmon.Interface{
					Interface: &net.Interface{
						Index:        iff.Index,
						MTU:          iff.MTU,
						Name:         iff.Name,
						HardwareAddr: iff.HardwareAddr,
						Flags:        iff.Flags,
					},
					AltAddrs: addrs,
				})
			}

			log.Debugln("[Tailscale] InterfaceGetter: %v", lo.Map(nif, func(item netmon.Interface, index int) string {
				var addrs any
				addrs, err := item.Addrs()
				if err != nil {
					addrs = err
				}
				return fmt.Sprintf("{Name: %s, Addrs: %v, IsUp: %v, IsLoopback: %v}", item.Name, addrs, item.IsUp(), item.IsLoopback())
			}))
			return
		})
	}
}

func NewTailscale(option TailscaleOption) (*Tailscale, error) {
	if _, err := buildTailscaleMaskedPrefs(option); err != nil {
		return nil, err
	}
	if option.StateDir == "" {
		option.StateDir = "tailscale"
	}
	stateDir, err := resolveTailscaleStateDir(option.StateDir)
	if err != nil {
		return nil, err
	}
	option.StateDir = stateDir

	addr := option.ControlURL
	if addr == "" {
		addr = "tailscale"
	}
	ctx, cancel := context.WithCancel(context.Background())
	outbound := &Tailscale{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Tailscale,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option:     option,
		sessionKey: tailscaleSessionKey(option),
		seq:        tailscaleOutboundSeq.Add(1),
		ctx:        ctx,
		cancel:     cancel,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	outbound.dnsTransport = tailscaleDNSTransport{tailscale: outbound}
	outbound.dnsResolver = dns.NewResolverFromClient(outbound.dnsTransport)
	return outbound, nil
}

// serverFactory must not capture the outbound: a pooled session outlives the
// config that created it, and the outbound's finalizer releases the session.
func (t *Tailscale) serverFactory() func(authKey string) *tsnet.Server {
	option := t.option
	systemDialer := t.dialer
	return func(authKey string) *tsnet.Server {
		if authKey == "" {
			authKey = option.AuthKey
		}
		return &tsnet.Server{
			Dir:        option.StateDir,
			Hostname:   option.Hostname,
			AuthKey:    authKey,
			ControlURL: option.ControlURL,
			Ephemeral:  option.Ephemeral,
			SystemDialer: func(ctx context.Context, network, address string) (net.Conn, error) {
				log.Debugln("[Tailscale](%s) SystemDialer: start dial %s %s", option.Name, network, address)
				conn, err := systemDialer.DialContext(ctx, network, address)
				log.Debugln("[Tailscale](%s) SystemDialer: finish dial %s %s, err: %v", option.Name, network, address, err)
				return conn, err
			},
			SystemPacketListener: func(ctx context.Context, network, address string) (net.PacketConn, error) {
				log.Debugln("[Tailscale](%s) SystemPacketListener: start listen %s %s", option.Name, network, address)
				pc, err := systemDialer.ListenPacket(ctx, network, address, netip.AddrPort{})
				log.Debugln("[Tailscale](%s) SystemPacketListener: finish listen %s %s, err: %v", option.Name, network, address, err)
				return pc, err
			},
			ExtraRootCAs: ca.GetCertPool(),
			LookupHook: func(ctx context.Context, host string) ([]netip.Addr, error) {
				log.Debugln("[Tailscale](%s) LookupHook: start lookup %s", option.Name, host)
				ips, err := resolver.LookupIPWithResolver(ctx, host, resolver.ProxyServerHostResolver)
				log.Debugln("[Tailscale](%s) LookupHook: finish lookup %s, ips: %v, err: %v", option.Name, host, ips, err)
				return ips, err
			},
			UserLogf: func(format string, args ...any) {
				log.Infoln("[Tailscale](%s) %s", option.Name, fmt.Sprintf(format, args...))
			},
			Logf: func(format string, args ...any) {
				log.Debugln("[Tailscale](%s) %s", option.Name, fmt.Sprintf(format, args...))
			},
		}
	}
}

// acquireSession returns the session serving this outbound. The routes and
// the tailscale:// DNS client are published only then, so an outbound parsed
// just to validate a config never replaces the running one's. authKey applies
// only if this call creates the session.
func (t *Tailscale) acquireSession(authKey string) (*tailscaleSession, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil, errTailscaleClosed
	}
	if session := t.session; session != nil {
		if !session.isClosed() {
			return session, nil
		}
		if err := session.closeError(); !errors.Is(err, errTailscaleRetired) {
			return nil, err
		}
		t.releaseLocked()
	}
	option := t.option
	key := t.sessionKey
	newServer := t.serverFactory()
	session, err := tailscaleSessions.acquire(option.StateDir, key, t.seq, func() *tailscaleSession {
		return newTailscaleSession(option, key, authKey, newServer)
	})
	if err != nil {
		return nil, err
	}
	t.session = session
	unregisterRoutes := tailnet.Register(t.Name(), session)
	unregisterDNS := dns.RegisterTailscaleDnsClient(t.Name(), t.dnsTransport)
	t.unregister = func() {
		unregisterRoutes()
		unregisterDNS()
	}
	return session, nil
}

func (t *Tailscale) releaseLocked() {
	if t.session == nil {
		return
	}
	t.unregister()
	tailscaleSessions.release(t.session)
	t.session = nil
	t.unregister = nil
}

// currentSession returns the live session serving this outbound without
// starting one.
func (t *Tailscale) currentSession() *tailscaleSession {
	t.mu.Lock()
	session := t.session
	t.mu.Unlock()
	if session != nil && !session.isClosed() {
		return session
	}
	if current := tailscaleSessions.peek(t.option.StateDir, t.sessionKey); current != nil {
		return current
	}
	return session
}

func (t *Tailscale) ensureStarted(ctx context.Context) (*tailscaleSession, error) {
	session, err := t.acquireSession("")
	if err != nil {
		return nil, err
	}
	if _, err = session.start(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(t.ctx, cancel)
	defer stop()
	if err = session.waitBackendInitialized(ctx); err != nil {
		if t.ctx.Err() != nil {
			return nil, errTailscaleClosed
		}
		return nil, err
	}
	return session, nil
}

// Warm starts a network that can come up without the user: one that is signed
// in or has an auth key. Any other network waits for Login, so a config apply
// never requests a login page.
func (t *Tailscale) Warm() {
	if t.option.AuthKey == "" && !tailscaleSignedIn(t.option.StateDir) {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(t.ctx, 30*time.Second)
		defer cancel()
		if _, err := t.ensureStarted(ctx); err != nil && t.ctx.Err() == nil {
			log.Warnln("[Tailscale](%s) start failed: %v", t.Name(), err)
		}
	}()
}

// Login asks control to authorize this device, with authKey when given and
// interactively otherwise; the login page then appears in Status as AuthURL.
func (t *Tailscale) Login(ctx context.Context, authKey string) error {
	session, err := t.acquireSession(authKey)
	if err != nil {
		return err
	}
	startedNow, err := session.start()
	if err != nil {
		return err
	}
	if err = session.waitBackendInitialized(ctx); err != nil {
		return err
	}
	if startedNow {
		// tsnet begins the login itself, with the key or interactively.
		return nil
	}
	lc, err := session.server.LocalClient()
	if err != nil {
		return err
	}
	status, err := lc.StatusWithoutPeers(ctx)
	if err != nil {
		return err
	}
	switch status.BackendState {
	case ipn.Running.String(), ipn.Starting.String():
		return nil
	case ipn.Stopped.String():
		_, err = lc.EditPrefs(ctx, &ipn.MaskedPrefs{
			Prefs:          ipn.Prefs{WantRunning: true},
			WantRunningSet: true,
		})
		return err
	}
	if authKey == "" && status.AuthURL != "" {
		return nil
	}
	// A key only reaches control when a control client starts, and asking a
	// running backend for another interactive login registers a second node
	// key. A fresh session starts exactly one login either way.
	tailscaleSessions.retire(session)
	session, err = t.acquireSession(authKey)
	if err != nil {
		return err
	}
	if session.authKey != authKey {
		return errors.New("tailscale login is already in progress, try again")
	}
	_, err = session.start()
	return err
}

// Logout signs this device out. The session is then retired, because a
// logout resets the control URL and hostname a fresh session restores.
func (t *Tailscale) Logout(ctx context.Context) error {
	session := t.currentSession()
	if session == nil || session.isClosed() || !session.isStarted() {
		return errTailscaleNotRunning
	}
	lc, err := session.server.LocalClient()
	if err != nil {
		return err
	}
	if err = lc.Logout(ctx); err != nil {
		return err
	}
	tailscaleSessions.retire(session)
	return nil
}

// Status reports the session without starting it.
func (t *Tailscale) Status(ctx context.Context) (*TailscaleStatus, error) {
	session := t.currentSession()
	if session == nil || (session.isClosed() && errors.Is(session.closeError(), errTailscaleRetired)) || !session.isStarted() {
		return &TailscaleStatus{State: TailscaleIdle, Peers: []TailscaleDevice{}}, nil
	}
	if session.isClosed() {
		return &TailscaleStatus{State: TailscaleIdle, Error: session.closeError().Error(), Peers: []TailscaleDevice{}}, nil
	}
	lc, err := session.server.LocalClient()
	if err != nil {
		return nil, err
	}
	status, err := lc.Status(ctx)
	if err != nil {
		return nil, err
	}
	return tailscaleStatusFrom(status), nil
}

// HasExitNode reports whether Internet traffic sent to this outbound has a
// configured way out of the tailnet.
func (t *Tailscale) HasExitNode() bool {
	return t.option.ExitNode != ""
}

// PingPeers measures the tailnet itself: the first disco pong from up to three
// peers, online and direct ones first. It needs no Internet egress.
func (t *Tailscale) PingPeers(ctx context.Context) (time.Duration, error) {
	session, err := t.ensureStarted(ctx)
	if err != nil {
		return 0, err
	}
	lc, err := session.server.LocalClient()
	if err != nil {
		return 0, err
	}
	status, err := lc.Status(ctx)
	if err != nil {
		return 0, err
	}
	if status.BackendState != ipn.Running.String() {
		return 0, fmt.Errorf("tailscale is %s", status.BackendState)
	}
	var candidates []*ipnstate.PeerStatus
	for _, peer := range status.Peer {
		if len(peer.TailscaleIPs) > 0 {
			candidates = append(candidates, peer)
		}
	}
	if len(candidates) == 0 {
		return 0, errors.New("no tailscale peer")
	}
	// Control's online flag is advisory: a peer it calls offline may only have
	// lost its control connection, so it is tried after the online ones.
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Online != candidates[j].Online {
			return candidates[i].Online
		}
		return candidates[i].CurAddr != "" && candidates[j].CurAddr == ""
	})
	if len(candidates) > 3 {
		candidates = candidates[:3]
	}
	pingCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type pingResult struct {
		latency time.Duration
		err     error
	}
	results := make(chan pingResult, len(candidates))
	for _, peer := range candidates {
		go func(addr netip.Addr) {
			result, err := lc.Ping(pingCtx, addr, tailcfg.PingDisco)
			switch {
			case err != nil:
				results <- pingResult{err: err}
			case result.Err != "":
				results <- pingResult{err: errors.New(result.Err)}
			default:
				results <- pingResult{latency: time.Duration(result.LatencySeconds * float64(time.Second))}
			}
		}(peer.TailscaleIPs[0])
	}
	var lastErr error
	for range candidates {
		result := <-results
		if result.err == nil {
			return result.latency, nil
		}
		lastErr = result.err
	}
	return 0, lastErr
}

func buildTailscaleMaskedPrefs(option TailscaleOption) (*ipn.MaskedPrefs, error) {
	var mp ipn.MaskedPrefs
	changed := false

	if option.AcceptRoutes != nil {
		mp.RouteAll = *option.AcceptRoutes
		mp.RouteAllSet = true
		changed = true
	}
	if option.ExitNode != "" {
		if autoExitNode, ok := ipn.ParseAutoExitNodeString(option.ExitNode); ok {
			mp.AutoExitNode = autoExitNode
			mp.AutoExitNodeSet = true
			changed = true
		}
	}
	if option.ExitNodeAllowLANAccess != nil && !tailscaleExitNodeNeedsStatus(option) {
		mp.ExitNodeAllowLANAccess = *option.ExitNodeAllowLANAccess
		mp.ExitNodeAllowLANAccessSet = true
		changed = true
	}
	if !changed {
		return nil, nil
	}
	return &mp, nil
}

func tailscaleExitNodeNeedsStatus(option TailscaleOption) bool {
	if option.ExitNode == "" {
		return false
	}
	_, ok := ipn.ParseAutoExitNodeString(option.ExitNode)
	return !ok
}

func (t *Tailscale) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	session, err := t.ensureStarted(ctx)
	if err != nil {
		return nil, err
	}
	netStack, err := session.server.Netstack(ctx)
	if err != nil {
		return nil, err
	}
	v4, v6 := session.server.TailscaleIPs()
	options := t.DialOptions()
	options = append(options, dialer.WithResolver(t.dnsResolver))
	options = append(options, dialer.WithNetDialer(dialer.NetDialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		dst, err := netip.ParseAddrPort(address) // the dialer will resolve the domain to ip
		if err != nil {
			return nil, err
		}
		src := v4
		if dst.Addr().Is6() {
			src = v6
		}
		tcpConn, err := netStack.DialContextTCPWithBind(ctx, src, dst)
		if err != nil {
			return nil, err
		}
		return tcpConn, nil
	})))
	var conn net.Conn
	conn, err = dialer.NewDialer(options...).DialContext(ctx, "tcp", metadata.RemoteAddress())
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, errors.New("conn is nil")
	}
	return NewConn(conn, t), nil
}

func (t *Tailscale) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	session, err := t.ensureStarted(ctx)
	if err != nil {
		return nil, err
	}
	if err = t.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	v4, v6 := session.server.TailscaleIPs()
	src := v4
	if metadata.DstIP.Is6() {
		src = v6
	}
	pc, err := session.server.ListenPacket("udp", net.JoinHostPort(src.String(), "0"))
	if err != nil {
		return nil, err
	}
	if pc == nil {
		return nil, errors.New("packetConn is nil")
	}
	return NewPacketConn(pc, t), nil
}

func (t *Tailscale) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	if metadata.Host != "" {
		ip, err := resolveIPWithResolver(ctx, metadata.Host, t.prefer, t.dnsResolver)
		if err != nil {
			return fmt.Errorf("can't resolve ip: %w", err)
		}
		metadata.DstIP = ip
	}
	return nil
}

type tailscaleDNSTransport struct {
	tailscale *Tailscale
}

func (t tailscaleDNSTransport) Address() string {
	return "tailscale://" + t.tailscale.Name()
}

func (t tailscaleDNSTransport) ResetConnection() {}

func (t tailscaleDNSTransport) ExchangeContext(ctx context.Context, msg *D.Msg) (*D.Msg, error) {
	if len(msg.Question) == 0 {
		return nil, errors.New("should have one question at least")
	}
	session, err := t.tailscale.ensureStarted(ctx)
	if err != nil {
		return nil, err
	}
	q := msg.Question[0]
	qtypeName, ok := D.TypeToString[q.Qtype]
	if !ok {
		return nil, fmt.Errorf("unsupported query type: %d", q.Qtype)
	}
	lc, err := session.server.LocalClient()
	if err != nil {
		return nil, err
	}
	response, _, err := lc.QueryDNS(ctx, q.Name, qtypeName)
	if err != nil {
		return nil, err
	}
	var responseMsg D.Msg
	if err = responseMsg.Unpack(response); err != nil {
		return nil, err
	}
	responseMsg.Id = msg.Id
	return &responseMsg, nil
}

func (t *Tailscale) ProxyInfo() C.ProxyInfo {
	info := t.Base.ProxyInfo()
	info.DialerProxy = t.option.DialerProxy
	return info
}

func (t *Tailscale) IsL3Protocol(metadata *C.Metadata) bool {
	return true
}

// Close releases the pooled session; it stops only when no newer outbound
// picks it up within the linger period.
func (t *Tailscale) Close() error {
	t.cancel()
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.closed {
		t.closed = true
		t.releaseLocked()
	}
	return nil
}
