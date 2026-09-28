//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/component/tailnet"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/tailscale/ipn"
	"github.com/metacubex/tailscale/ipn/ipnstate"
	"github.com/metacubex/tailscale/tsnet"
)

// Every config apply parses a new outbound. Sessions are pooled by state
// directory so an unchanged outbound keeps its connection across applies and
// two tsnet servers never run on one node identity.
var tailscaleSessionLinger = time.Minute

const (
	tailscaleRoutesDebounce  = time.Second
	tailscaleRoutesRefresh   = time.Minute
	tailscaleStatusTimeout   = 5 * time.Second
	tailscaleStateFileName   = "tailscaled.state"
	tailscaleWatchRetryDelay = time.Second
)

type tailscaleSessionPool struct {
	mu        sync.Mutex
	byDir     map[string]*tailscaleSession
	forgotten map[string]struct{}
}

var tailscaleSessions = &tailscaleSessionPool{
	byDir:     map[string]*tailscaleSession{},
	forgotten: map[string]struct{}{},
}

func (p *tailscaleSessionPool) acquire(stateDir, key string, create func() *tailscaleSession) (*tailscaleSession, error) {
	p.mu.Lock()
	if _, ok := p.forgotten[stateDir]; ok {
		p.mu.Unlock()
		return nil, errTailscaleRemoved
	}
	var superseded *tailscaleSession
	if current := p.byDir[stateDir]; current != nil {
		if current.key == key && !current.isClosed() {
			current.refs++
			if current.linger != nil {
				current.linger.Stop()
				current.linger = nil
			}
			p.mu.Unlock()
			return current, nil
		}
		superseded = current
	}
	session := create()
	session.refs = 1
	p.byDir[stateDir] = session
	p.mu.Unlock()
	if superseded != nil {
		superseded.close(errTailscaleSuperseded)
	}
	return session, nil
}

// peek returns the pooled session without taking a reference.
func (p *tailscaleSessionPool) peek(stateDir, key string) *tailscaleSession {
	p.mu.Lock()
	defer p.mu.Unlock()
	if current := p.byDir[stateDir]; current != nil && current.key == key && !current.isClosed() {
		return current
	}
	return nil
}

func (p *tailscaleSessionPool) release(session *tailscaleSession) {
	p.mu.Lock()
	defer p.mu.Unlock()
	session.refs--
	if session.refs > 0 || session.isClosed() {
		return
	}
	session.linger = time.AfterFunc(tailscaleSessionLinger, func() {
		p.mu.Lock()
		if session.refs > 0 || p.byDir[session.stateDir] != session {
			p.mu.Unlock()
			return
		}
		delete(p.byDir, session.stateDir)
		p.mu.Unlock()
		session.close(errTailscaleClosed)
	})
}

func (p *tailscaleSessionPool) drop(session *tailscaleSession) {
	p.mu.Lock()
	if p.byDir[session.stateDir] == session {
		delete(p.byDir, session.stateDir)
	}
	p.mu.Unlock()
}

func (p *tailscaleSessionPool) forget(stateDir string) {
	p.mu.Lock()
	p.forgotten[stateDir] = struct{}{}
	session := p.byDir[stateDir]
	delete(p.byDir, stateDir)
	p.mu.Unlock()
	if session != nil {
		session.close(errTailscaleRemoved)
	}
}

// ForgetTailscaleState stops the session of a removed network and deletes its
// node identity. The directory can never be used again by this process.
func ForgetTailscaleState(stateDir string) error {
	resolved, err := resolveTailscaleStateDir(stateDir)
	if err != nil {
		return err
	}
	tailscaleSessions.forget(resolved)
	return os.RemoveAll(resolved)
}

func resolveTailscaleStateDir(stateDir string) (string, error) {
	if strings.TrimSpace(stateDir) == "" {
		return "", errors.New("missing tailscale state-dir")
	}
	resolved := C.Path.Resolve(stateDir)
	if !C.Path.IsSafePath(resolved) {
		return "", C.Path.ErrNotSafePath(resolved)
	}
	return resolved, nil
}

func tailscaleStateExists(stateDir string) bool {
	info, err := os.Stat(filepath.Join(stateDir, tailscaleStateFileName))
	return err == nil && info.Size() > 0
}

type tailscaleSession struct {
	stateDir  string
	key       string
	option    TailscaleOption
	newServer func(authKey string) *tsnet.Server

	ctx    context.Context
	cancel context.CancelFunc

	// mu serializes Start and Close, which tsnet forbids running concurrently.
	mu            sync.Mutex
	server        *tsnet.Server
	started       bool
	serverRunning bool
	closeErr      error

	backendInitOnce sync.Once
	backendInitCh   chan struct{}
	backendInitErr  error

	// refs and linger are guarded by the pool.
	refs   int
	linger *time.Timer

	closed atomic.Bool

	routes        atomic.Pointer[tailnet.Routes]
	refreshRoutes chan struct{}
}

func newTailscaleSession(option TailscaleOption, key string, newServer func(string) *tsnet.Server) *tailscaleSession {
	ctx, cancel := context.WithCancel(context.Background())
	return &tailscaleSession{
		stateDir:      option.StateDir,
		key:           key,
		option:        option,
		newServer:     newServer,
		ctx:           ctx,
		cancel:        cancel,
		backendInitCh: make(chan struct{}),
		refreshRoutes: make(chan struct{}, 1),
	}
}

func (s *tailscaleSession) Routes() *tailnet.Routes {
	return s.routes.Load()
}

func (s *tailscaleSession) isClosed() bool {
	return s.closed.Load()
}

func (s *tailscaleSession) closeError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closeErr == nil {
		return errTailscaleClosed
	}
	return s.closeErr
}

func (s *tailscaleSession) isStarted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.started
}

// start launches tsnet once. authKey is only used when this call starts it.
func (s *tailscaleSession) start(authKey string) (startedNow bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isClosed() {
		return false, s.closeErr
	}
	if s.started {
		return false, nil
	}
	s.started = true
	s.server = s.newServer(authKey)
	if err = s.server.Start(); err != nil {
		s.failLocked(err)
		return true, err
	}
	s.serverRunning = true
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()
	if err = s.applyPrefs(ctx); err != nil {
		s.failLocked(err)
		return true, err
	}
	go s.watchBackendState()
	go s.watchRoutes()
	return true, nil
}

// failLocked retires a session that could not start, so the next config
// apply builds a fresh one instead of inheriting the failure.
func (s *tailscaleSession) failLocked(err error) {
	s.closeLocked(err)
	tailscaleSessions.drop(s)
}

func (s *tailscaleSession) close(reason error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeLocked(reason)
}

func (s *tailscaleSession) closeLocked(reason error) {
	if s.closed.Load() {
		return
	}
	s.closeErr = reason
	s.closed.Store(true)
	s.cancel()
	s.setBackendInitialized(reason)
	s.routes.Store(nil)
	if s.serverRunning {
		s.serverRunning = false
		if err := s.server.Close(); err != nil {
			log.Warnln("[Tailscale] close %s: %v", s.stateDir, err)
		}
	}
}

func (s *tailscaleSession) setBackendInitialized(err error) {
	s.backendInitOnce.Do(func() {
		s.backendInitErr = err
		close(s.backendInitCh)
	})
}

func (s *tailscaleSession) waitBackendInitialized(ctx context.Context) error {
	select {
	case <-s.backendInitCh:
		return s.backendInitErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *tailscaleSession) watchBackendState() {
	lc, err := s.server.LocalClient()
	if err != nil {
		s.setBackendInitialized(err)
		return
	}
	watcher, err := lc.WatchIPNBus(s.ctx, ipn.NotifyInitialState)
	if err != nil {
		s.setBackendInitialized(err)
		return
	}
	defer watcher.Close()

	backendInitialized := false
	exitNodeNeedsStatus := tailscaleExitNodeNeedsStatus(s.option)
	for {
		n, err := watcher.Next()
		if err != nil {
			s.setBackendInitialized(err)
			return
		}
		if n.State == nil {
			continue
		}

		if *n.State != ipn.NoState && !backendInitialized {
			s.setBackendInitialized(nil)
			backendInitialized = true
			if !exitNodeNeedsStatus {
				return
			}
		}
		if exitNodeNeedsStatus && *n.State == ipn.Running {
			if err := s.applyExitNodePrefs(s.ctx); err != nil {
				log.Warnln("[Tailscale](%s) set exit node failed: %v", s.stateDir, err)
			}
			return
		}
	}
}

func (s *tailscaleSession) applyPrefs(ctx context.Context) error {
	mp, err := buildTailscaleMaskedPrefs(s.option)
	if err != nil {
		return err
	}
	if mp == nil {
		return nil
	}
	lc, err := s.server.LocalClient()
	if err != nil {
		return err
	}
	_, err = lc.EditPrefs(ctx, mp)
	return err
}

func (s *tailscaleSession) applyExitNodePrefs(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	lc, err := s.server.LocalClient()
	if err != nil {
		return err
	}
	status, err := lc.Status(ctx)
	if err != nil {
		return err
	}
	mp := &ipn.MaskedPrefs{
		ExitNodeIPSet: true,
	}
	if s.option.ExitNodeAllowLANAccess != nil {
		mp.ExitNodeAllowLANAccess = *s.option.ExitNodeAllowLANAccess
		mp.ExitNodeAllowLANAccessSet = true
	}
	if err = mp.SetExitNodeIP(s.option.ExitNode, status); err != nil {
		return err
	}
	_, err = lc.EditPrefs(ctx, mp)
	return err
}

// watchRoutes rebuilds the TAILNET routes whenever peers or the backend state
// change. Legacy netmap notifications are not emitted on every platform, so
// peer-change notifications only trigger a fresh status read.
func (s *tailscaleSession) watchRoutes() {
	lc, err := s.server.LocalClient()
	if err != nil {
		return
	}
	go s.refreshRoutesLoop()
	mask := ipn.NotifyInitialState | ipn.NotifyPeerChanges | ipn.NotifyNoNetMap
	for s.ctx.Err() == nil {
		watcher, err := lc.WatchIPNBus(s.ctx, mask)
		if err != nil {
			select {
			case <-time.After(tailscaleWatchRetryDelay):
				continue
			case <-s.ctx.Done():
				return
			}
		}
		for {
			if _, err := watcher.Next(); err != nil {
				break
			}
			select {
			case s.refreshRoutes <- struct{}{}:
			default:
			}
		}
		_ = watcher.Close()
	}
}

func (s *tailscaleSession) refreshRoutesLoop() {
	ticker := time.NewTicker(tailscaleRoutesRefresh)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
		case <-s.refreshRoutes:
			// Coalesce the burst of notifications a netmap change produces.
			select {
			case <-time.After(tailscaleRoutesDebounce):
			case <-s.ctx.Done():
				return
			}
		}
		s.updateRoutes()
	}
}

func (s *tailscaleSession) updateRoutes() {
	lc, err := s.server.LocalClient()
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, tailscaleStatusTimeout)
	defer cancel()
	status, err := lc.Status(ctx)
	if err != nil {
		return
	}
	if s.isClosed() {
		return
	}
	s.routes.Store(buildTailnetRoutes(status))
}

func tailscaleMagicDNSSuffix(status *ipnstate.Status) string {
	if status.CurrentTailnet != nil && status.CurrentTailnet.MagicDNSSuffix != "" {
		return status.CurrentTailnet.MagicDNSSuffix
	}
	return status.MagicDNSSuffix
}

// buildTailnetRoutes lists peer addresses, their MagicDNS names, the short
// names no two peers share, and the tailnet suffix. Subnet routes and exit
// traffic are left to explicit rules.
func buildTailnetRoutes(status *ipnstate.Status) *tailnet.Routes {
	if status.BackendState != ipn.Running.String() {
		return nil
	}
	suffix := tailnet.NormalizeName(tailscaleMagicDNSSuffix(status))
	var names []string
	var addrs []netip.Addr
	shortNames := map[string]int{}
	for _, peer := range status.Peer {
		addrs = append(addrs, peer.TailscaleIPs...)
		name := tailnet.NormalizeName(peer.DNSName)
		if name == "" {
			continue
		}
		names = append(names, name)
		if short, _, ok := strings.Cut(name, "."); ok && short != "" {
			shortNames[short]++
		}
	}
	for short, count := range shortNames {
		if count == 1 {
			names = append(names, short)
		}
	}
	var suffixes []string
	if suffix != "" {
		suffixes = append(suffixes, suffix)
	}
	return tailnet.NewRoutes(suffixes, names, addrs)
}

func tailscaleStatusFrom(status *ipnstate.Status) *TailscaleStatus {
	result := &TailscaleStatus{
		State:          status.BackendState,
		AuthURL:        status.AuthURL,
		MagicDNSSuffix: tailnet.NormalizeName(tailscaleMagicDNSSuffix(status)),
		Health:         status.Health,
		Peers:          []TailscaleDevice{},
	}
	if status.CurrentTailnet != nil {
		result.Tailnet = status.CurrentTailnet.Name
	}
	if status.Self != nil {
		self := tailscaleDeviceFrom(status.Self)
		self.Addresses = tailscaleAddresses(status.TailscaleIPs)
		result.Self = &self
		result.KeyExpired = status.Self.Expired
		if status.Self.KeyExpiry != nil {
			result.KeyExpiry = status.Self.KeyExpiry.UnixMilli()
		}
	}
	for _, peer := range status.Peer {
		result.Peers = append(result.Peers, tailscaleDeviceFrom(peer))
	}
	sort.Slice(result.Peers, func(i, j int) bool {
		if result.Peers[i].Online != result.Peers[j].Online {
			return result.Peers[i].Online
		}
		return result.Peers[i].Name < result.Peers[j].Name
	})
	return result
}

func tailscaleDeviceFrom(peer *ipnstate.PeerStatus) TailscaleDevice {
	return TailscaleDevice{
		Name:           tailnet.NormalizeName(peer.DNSName),
		HostName:       peer.HostName,
		OS:             peer.OS,
		Addresses:      tailscaleAddresses(peer.TailscaleIPs),
		Online:         peer.Online,
		Direct:         peer.CurAddr != "",
		Relay:          peer.Relay,
		ExitNodeOption: peer.ExitNodeOption,
		ExitNode:       peer.ExitNode,
	}
}

func tailscaleAddresses(addrs []netip.Addr) []string {
	result := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		result = append(result, addr.String())
	}
	return result
}

// tailscaleSessionKey covers every option that shapes the tsnet server, so
// outbounds that would build different servers never share one.
func tailscaleSessionKey(option TailscaleOption) string {
	key, _ := json.Marshal(struct {
		Hostname               string
		AuthKey                string
		ControlURL             string
		Ephemeral              bool
		AcceptRoutes           *bool
		ExitNode               string
		ExitNodeAllowLANAccess *bool
		TFO                    bool
		MPTCP                  bool
		Interface              string
		RoutingMark            int
		IPVersion              C.DNSPrefer
		DialerProxy            string
	}{
		option.Hostname,
		option.AuthKey,
		option.ControlURL,
		option.Ephemeral,
		option.AcceptRoutes,
		option.ExitNode,
		option.ExitNodeAllowLANAccess,
		option.TFO,
		option.MPTCP,
		option.Interface,
		option.RoutingMark,
		option.IPVersion,
		option.DialerProxy,
	})
	return string(key)
}
