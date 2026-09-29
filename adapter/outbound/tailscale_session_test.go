//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/tailnet"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/tailscale/ipn"
	"github.com/metacubex/tailscale/ipn/ipnstate"
	"github.com/metacubex/tailscale/types/key"
	"github.com/metacubex/tailscale/types/views"
	"github.com/stretchr/testify/require"
)

func testSessionFactory(dir, key string) func() *tailscaleSession {
	return func() *tailscaleSession {
		return newTailscaleSession(TailscaleOption{StateDir: dir}, key, "", nil)
	}
}

func TestTailscaleSessionPoolSharesMatchingSession(t *testing.T) {
	pool := newTailscaleSessionPool()
	first, err := pool.acquire("/state/a", "key", 1, testSessionFactory("/state/a", "key"))
	require.NoError(t, err)
	second, err := pool.acquire("/state/a", "key", 2, testSessionFactory("/state/a", "key"))
	require.NoError(t, err)
	require.Same(t, first, second)
	require.Same(t, first, pool.peek("/state/a", "key"))
	require.Nil(t, pool.peek("/state/a", "other"))
}

func TestTailscaleSessionPoolLetsOnlyNewerOutboundsReplace(t *testing.T) {
	pool := newTailscaleSessionPool()
	current, err := pool.acquire("/state/a", "current", 5, testSessionFactory("/state/a", "current"))
	require.NoError(t, err)

	// An outbound parsed earlier, such as one an old config still holds,
	// cannot take the directory back.
	_, err = pool.acquire("/state/a", "stale", 4, testSessionFactory("/state/a", "stale"))
	require.ErrorIs(t, err, errTailscaleSuperseded)
	require.False(t, current.isClosed())

	replacement, err := pool.acquire("/state/a", "changed", 6, testSessionFactory("/state/a", "changed"))
	require.NoError(t, err)
	require.Equal(t, (<-chan struct{})(current.done), replacement.predecessor, "the new server waits for the old one")
	require.Eventually(t, current.isClosed, time.Second, 5*time.Millisecond)
	require.ErrorIs(t, current.closeError(), errTailscaleSuperseded)
	_, err = current.start()
	require.ErrorIs(t, err, errTailscaleSuperseded)
}

func TestTailscaleSessionPoolLingersBeforeClosing(t *testing.T) {
	previous := tailscaleSessionLinger
	tailscaleSessionLinger = 20 * time.Millisecond
	defer func() { tailscaleSessionLinger = previous }()

	pool := newTailscaleSessionPool()
	session, err := pool.acquire("/state/a", "key", 1, testSessionFactory("/state/a", "key"))
	require.NoError(t, err)
	pool.release(session)

	// A newer outbound picking the session up inside the linger keeps it.
	again, err := pool.acquire("/state/a", "key", 2, testSessionFactory("/state/a", "key"))
	require.NoError(t, err)
	require.Same(t, session, again)
	time.Sleep(3 * tailscaleSessionLinger)
	require.False(t, session.isClosed())

	pool.release(again)
	require.Eventually(t, session.isClosed, time.Second, 5*time.Millisecond)
	require.Nil(t, pool.peek("/state/a", "key"))
	require.Nil(t, session.Routes(), "a closed session publishes no routes")
}

func TestTailscaleSessionPoolRetiresForAFreshStart(t *testing.T) {
	pool := newTailscaleSessionPool()
	session, err := pool.acquire("/state/a", "key", 1, testSessionFactory("/state/a", "key"))
	require.NoError(t, err)
	pool.retire(session)
	require.ErrorIs(t, session.closeError(), errTailscaleRetired)

	fresh, err := pool.acquire("/state/a", "key", 1, testSessionFactory("/state/a", "key"))
	require.NoError(t, err)
	require.NotSame(t, session, fresh)
	require.Nil(t, fresh.predecessor)
	require.Empty(t, pool.closing)
}

func TestForgetTailscaleStateDeletesIdentity(t *testing.T) {
	previousHome := C.Path.HomeDir()
	home := t.TempDir()
	C.SetHomeDir(home)
	defer C.SetHomeDir(previousHome)

	stateDir := filepath.Join(home, "tailscale-networks", "network")
	require.NoError(t, os.MkdirAll(stateDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(stateDir, tailscaleStateFileName), []byte("{}"), 0o600))

	parsedBefore := tailscaleOutboundSeq.Add(1)
	session, err := tailscaleSessions.acquire(stateDir, "key", parsedBefore, testSessionFactory(stateDir, "key"))
	require.NoError(t, err)

	require.NoError(t, ForgetTailscaleState("tailscale-networks/network/"))
	require.True(t, session.isClosed())
	require.ErrorIs(t, session.closeError(), errTailscaleRemoved)
	_, err = os.Stat(stateDir)
	require.True(t, os.IsNotExist(err))
	_, err = tailscaleSessions.acquire(stateDir, "key", parsedBefore, testSessionFactory(stateDir, "key"))
	require.ErrorIs(t, err, errTailscaleRemoved)

	// A network restored later is parsed again and may use the directory.
	restored, err := tailscaleSessions.acquire(stateDir, "key", tailscaleOutboundSeq.Add(1), testSessionFactory(stateDir, "key"))
	require.NoError(t, err)
	tailscaleSessions.retire(restored)

	require.Error(t, ForgetTailscaleState(""))
}

func TestTailscaleSignedInNeedsALoginProfile(t *testing.T) {
	dir := t.TempDir()
	require.False(t, tailscaleSignedIn(dir), "no state file")

	write := func(profiles string) {
		t.Helper()
		data, err := json.Marshal(map[string][]byte{
			"_machinekey": []byte("privkey:00"),
			"_profiles":   []byte(profiles),
		})
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, tailscaleStateFileName), data, 0o600))
	}
	write(`{}`)
	require.False(t, tailscaleSignedIn(dir), "a node that never signed in, or logged out")
	write(`{"a1b2":{"ID":"a1b2"}}`)
	require.True(t, tailscaleSignedIn(dir))
	require.NoError(t, os.WriteFile(filepath.Join(dir, tailscaleStateFileName), []byte("not json"), 0o600))
	require.False(t, tailscaleSignedIn(dir))
}

func TestTailscaleSessionKeyTracksServerOptions(t *testing.T) {
	base := TailscaleOption{Name: "Home", StateDir: "/state/a", Hostname: "phone"}
	renamed := base
	renamed.Name = "Renamed"
	renamed.UDP = true
	require.Equal(t, tailscaleSessionKey(base), tailscaleSessionKey(renamed))

	for _, change := range []func(*TailscaleOption){
		func(o *TailscaleOption) { o.Hostname = "laptop" },
		func(o *TailscaleOption) { o.ControlURL = "https://headscale.example" },
		func(o *TailscaleOption) { o.ExitNode = "auto:any" },
		func(o *TailscaleOption) { o.DialerProxy = "Relay" },
		func(o *TailscaleOption) { accept := true; o.AcceptRoutes = &accept },
	} {
		changed := base
		change(&changed)
		require.NotEqual(t, tailscaleSessionKey(base), tailscaleSessionKey(changed))
	}
}

func testPeer(dnsName string, online bool, addrs ...string) *ipnstate.PeerStatus {
	peer := &ipnstate.PeerStatus{DNSName: dnsName, Online: online, HostName: dnsName}
	for _, addr := range addrs {
		peer.TailscaleIPs = append(peer.TailscaleIPs, netip.MustParseAddr(addr))
	}
	return peer
}

func TestBuildTailnetRoutes(t *testing.T) {
	status := &ipnstate.Status{
		BackendState:   ipn.Running.String(),
		CurrentTailnet: &ipnstate.TailnetStatus{MagicDNSSuffix: "tail1234.ts.net"},
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			key.NewNode().Public(): testPeer("nas.tail1234.ts.net.", true, "100.64.0.2", "fd7a:115c:a1e0::2"),
			key.NewNode().Public(): testPeer("office.tail1234.ts.net.", false, "100.64.0.3"),
			key.NewNode().Public(): testPeer("office.shared.ts.net.", true, "100.64.0.4"),
		},
	}
	routes := buildTailnetRoutes(status, true)
	for _, host := range []string{"nas", "nas.tail1234.ts.net", "printer.tail1234.ts.net", "tail1234.ts.net", "office.shared.ts.net"} {
		require.True(t, routes.MatchHost(host), host)
	}
	// Two peers share the short name, so it stays ambiguous.
	require.False(t, routes.MatchHost("office"))
	for _, addr := range []string{"100.64.0.2", "fd7a:115c:a1e0::2", "100.64.0.3", "100.64.0.4"} {
		require.True(t, routes.MatchAddr(netip.MustParseAddr(addr)), addr)
	}
	require.False(t, routes.MatchAddr(netip.MustParseAddr("100.64.0.9")))

	// A Headscale base domain may also serve public sites, so only its peers
	// are claimed, not the whole domain.
	status.CurrentTailnet.MagicDNSSuffix = "example.com"
	status.Peer[key.NewNode().Public()] = testPeer("vault.example.com.", true, "100.64.0.5")
	routes = buildTailnetRoutes(status, true)
	require.True(t, routes.MatchHost("vault.example.com"))
	require.True(t, routes.MatchHost("vault"))
	require.False(t, routes.MatchHost("www.example.com"))
	require.False(t, routes.MatchHost("example.com"))

	status.BackendState = ipn.NeedsLogin.String()
	require.Nil(t, buildTailnetRoutes(status, true))
}

func TestBuildTailnetRoutesClaimsApprovedSubnets(t *testing.T) {
	router := testPeer("router.tail1234.ts.net.", true, "100.64.0.6")
	primary := views.SliceOf([]netip.Prefix{
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("2001:db8:42::/64"),
		netip.MustParsePrefix("0.0.0.0/0"),
	})
	router.PrimaryRoutes = &primary
	status := &ipnstate.Status{
		BackendState: ipn.Running.String(),
		Peer:         map[key.NodePublic]*ipnstate.PeerStatus{key.NewNode().Public(): router},
	}
	routes := buildTailnetRoutes(status, true)
	for _, addr := range []string{"100.64.0.6", "198.51.100.7", "2001:db8:42::7", "::ffff:198.51.100.7"} {
		require.True(t, routes.MatchAddr(netip.MustParseAddr(addr)), addr)
	}
	// An exit default is not a subnet.
	require.False(t, routes.MatchAddr(netip.MustParseAddr("203.0.113.7")))

	// Without accepted routes tsnet cannot reach the subnet, so it stays unclaimed.
	routes = buildTailnetRoutes(status, false)
	require.True(t, routes.MatchAddr(netip.MustParseAddr("100.64.0.6")))
	require.False(t, routes.MatchAddr(netip.MustParseAddr("198.51.100.7")))
}

func TestTailscaleStatusOmitsCredentials(t *testing.T) {
	status := tailscaleStatusFrom(&ipnstate.Status{
		BackendState:   ipn.Running.String(),
		TailscaleIPs:   []netip.Addr{netip.MustParseAddr("100.64.0.1")},
		CurrentTailnet: &ipnstate.TailnetStatus{Name: "user@example.com", MagicDNSSuffix: "tail1234.ts.net"},
		Self:           &ipnstate.PeerStatus{DNSName: "phone.tail1234.ts.net."},
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			key.NewNode().Public(): testPeer("b.tail1234.ts.net.", false, "100.64.0.3"),
			key.NewNode().Public(): testPeer("a.tail1234.ts.net.", true, "100.64.0.2"),
		},
	})
	require.Equal(t, "Running", status.State)
	require.Equal(t, "user@example.com", status.Tailnet)
	require.Equal(t, "tail1234.ts.net", status.MagicDNSSuffix)
	require.Equal(t, "phone.tail1234.ts.net", status.Self.Name)
	require.Equal(t, []string{"100.64.0.1"}, status.Self.Addresses)
	require.Equal(t, "a.tail1234.ts.net", status.Peers[0].Name, "online peers first")
	require.Equal(t, "b.tail1234.ts.net", status.Peers[1].Name)
}

func TestTailscaleSharedSessionKeepsNewestOwner(t *testing.T) {
	pool := newTailscaleSessionPool()
	current, err := pool.acquire("/state/a", "key", 1, testSessionFactory("/state/a", "key"))
	require.NoError(t, err)
	shared, err := pool.acquire("/state/a", "key", 3, testSessionFactory("/state/a", "key"))
	require.NoError(t, err)
	require.Same(t, current, shared)
	_, err = pool.acquire("/state/a", "stale", 2, testSessionFactory("/state/a", "stale"))
	require.ErrorIs(t, err, errTailscaleSuperseded)
	require.False(t, current.isClosed())
}

func TestTailscalePrefsClearSavedExitNode(t *testing.T) {
	for _, exit := range []string{"", "auto:any", "100.64.0.2"} {
		t.Run(exit, func(t *testing.T) {
			prefs := &ipn.Prefs{
				ExitNodeID:             "old-exit",
				ExitNodeIP:             netip.MustParseAddr("100.64.0.9"),
				AutoExitNode:           "any",
				ExitNodeAllowLANAccess: true,
			}
			patch := buildTailscaleMaskedPrefs(TailscaleOption{ExitNode: exit})
			require.NotNil(t, patch)
			prefs.ApplyEdits(patch)
			require.Empty(t, prefs.ExitNodeID)
			require.False(t, prefs.ExitNodeIP.IsValid())
			require.False(t, prefs.ExitNodeAllowLANAccess)
			if exit == "auto:any" {
				require.Equal(t, "any", string(prefs.AutoExitNode))
			} else {
				require.Empty(t, prefs.AutoExitNode)
			}
		})
	}
}

func TestTailscaleSessionPoolReleasesClosedSessions(t *testing.T) {
	pool := newTailscaleSessionPool()
	session, err := pool.acquire("/state/a", "first", 1, testSessionFactory("/state/a", "first"))
	require.NoError(t, err)
	next, err := pool.acquire("/state/a", "second", 2, testSessionFactory("/state/a", "second"))
	require.NoError(t, err)
	<-session.done
	pool.retire(next)
	pool.mu.Lock()
	defer pool.mu.Unlock()
	require.Empty(t, pool.byDir)
	require.Empty(t, pool.closing)
}

type testTailnetRoutes struct{ routes *tailnet.Routes }

func (s testTailnetRoutes) Routes() *tailnet.Routes { return s.routes }

func TestTailscaleTrafficNeverBeginsALogin(t *testing.T) {
	useTailscaleHome(t)
	tailscale, err := NewTailscale(TailscaleOption{Name: "Idle", StateDir: "tailscale-networks/idle"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = tailscale.Close() })
	_, err = tailscale.DialContext(context.Background(), &C.Metadata{
		NetWork: C.TCP, DstIP: netip.MustParseAddr("100.64.0.2"), DstPort: 80,
	})
	require.ErrorIs(t, err, errTailscaleNeedsLogin)
	status, err := tailscale.Status(context.Background())
	require.NoError(t, err)
	require.Equal(t, TailscaleIdle, status.State, "a dial started the network")
}

func TestTailscaleExitNodeKeepsPublicNamesInTheTailnet(t *testing.T) {
	useTailscaleHome(t)
	tailscale, err := NewTailscale(TailscaleOption{
		Name: "Exit", StateDir: "tailscale-networks/exit", ExitNode: "auto",
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = tailscale.Close() })
	subnetHost := netip.MustParseAddr("198.51.100.1")
	unregister := tailnet.Register("Exit", testTailnetRoutes{tailnet.NewRoutes(
		nil, nil, nil, []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
	)})
	t.Cleanup(unregister)
	previous := resolver.DirectHostResolver
	resolver.DirectHostResolver = fixtureLocalResolver{"nas.fixture.invalid": subnetHost}
	t.Cleanup(func() { resolver.DirectHostResolver = previous })

	// The exit node's DNS answers public names, so the local answer is unused.
	_, ok := tailscale.routedAddr(context.Background(), &C.Metadata{Host: "nas.fixture.invalid"})
	require.False(t, ok)
	addr, ok := tailscale.routedAddr(context.Background(), &C.Metadata{Host: "nas.fixture.invalid", DstIP: subnetHost})
	require.True(t, ok, "an address the rules resolved into the tailnet is still dialed")
	require.Equal(t, subnetHost, addr)
}
