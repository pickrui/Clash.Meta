//go:build with_gvisor && !no_tailscale

package outbound

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/tailscale/ipn"
	"github.com/metacubex/tailscale/ipn/ipnstate"
	"github.com/metacubex/tailscale/types/key"
	"github.com/stretchr/testify/require"
)

func newTestSessionPool() *tailscaleSessionPool {
	return &tailscaleSessionPool{
		byDir:     map[string]*tailscaleSession{},
		forgotten: map[string]struct{}{},
	}
}

func testSessionFactory(dir, key string) func() *tailscaleSession {
	return func() *tailscaleSession {
		return newTailscaleSession(TailscaleOption{StateDir: dir}, key, nil)
	}
}

func TestTailscaleSessionPoolSharesMatchingSession(t *testing.T) {
	pool := newTestSessionPool()
	first, err := pool.acquire("/state/a", "key", testSessionFactory("/state/a", "key"))
	require.NoError(t, err)
	second, err := pool.acquire("/state/a", "key", testSessionFactory("/state/a", "key"))
	require.NoError(t, err)
	require.Same(t, first, second)
	require.Same(t, first, pool.peek("/state/a", "key"))
	require.Nil(t, pool.peek("/state/a", "other"))
}

func TestTailscaleSessionPoolSupersedesChangedOptions(t *testing.T) {
	pool := newTestSessionPool()
	old, err := pool.acquire("/state/a", "old", testSessionFactory("/state/a", "old"))
	require.NoError(t, err)
	replacement, err := pool.acquire("/state/a", "new", testSessionFactory("/state/a", "new"))
	require.NoError(t, err)
	require.NotSame(t, old, replacement)
	require.True(t, old.isClosed())
	require.ErrorIs(t, old.closeError(), errTailscaleSuperseded)
	_, err = old.start("")
	require.ErrorIs(t, err, errTailscaleSuperseded)
}

func TestTailscaleSessionPoolLingersBeforeClosing(t *testing.T) {
	previous := tailscaleSessionLinger
	tailscaleSessionLinger = 20 * time.Millisecond
	defer func() { tailscaleSessionLinger = previous }()

	pool := newTestSessionPool()
	session, err := pool.acquire("/state/a", "key", testSessionFactory("/state/a", "key"))
	require.NoError(t, err)
	pool.release(session)

	// A newer outbound picking the session up inside the linger keeps it.
	again, err := pool.acquire("/state/a", "key", testSessionFactory("/state/a", "key"))
	require.NoError(t, err)
	require.Same(t, session, again)
	time.Sleep(3 * tailscaleSessionLinger)
	require.False(t, session.isClosed())

	pool.release(again)
	require.Eventually(t, session.isClosed, time.Second, 5*time.Millisecond)
	require.Nil(t, pool.peek("/state/a", "key"))
}

func TestForgetTailscaleStateDeletesIdentity(t *testing.T) {
	previousHome := C.Path.HomeDir()
	home := t.TempDir()
	C.SetHomeDir(home)
	defer C.SetHomeDir(previousHome)

	stateDir := filepath.Join(home, "tailscale-networks", "network")
	require.NoError(t, os.MkdirAll(stateDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(stateDir, tailscaleStateFileName), []byte("{}"), 0o600))
	require.True(t, tailscaleStateExists(stateDir))

	session, err := tailscaleSessions.acquire(stateDir, "key", testSessionFactory(stateDir, "key"))
	require.NoError(t, err)

	require.NoError(t, ForgetTailscaleState("tailscale-networks/network"))
	require.True(t, session.isClosed())
	require.ErrorIs(t, session.closeError(), errTailscaleRemoved)
	_, err = os.Stat(stateDir)
	require.True(t, os.IsNotExist(err))
	_, err = tailscaleSessions.acquire(stateDir, "key", testSessionFactory(stateDir, "key"))
	require.ErrorIs(t, err, errTailscaleRemoved)

	require.Error(t, ForgetTailscaleState(""))
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
	routes := buildTailnetRoutes(status)
	for _, host := range []string{"nas", "nas.tail1234.ts.net", "printer.tail1234.ts.net", "office.shared.ts.net"} {
		require.True(t, routes.MatchHost(host), host)
	}
	// Two peers share the short name, so it stays ambiguous.
	require.False(t, routes.MatchHost("office"))
	for _, addr := range []string{"100.64.0.2", "fd7a:115c:a1e0::2", "100.64.0.3", "100.64.0.4"} {
		require.True(t, routes.MatchAddr(netip.MustParseAddr(addr)), addr)
	}
	require.False(t, routes.MatchAddr(netip.MustParseAddr("100.64.0.9")))

	status.BackendState = ipn.NeedsLogin.String()
	require.Nil(t, buildTailnetRoutes(status))
}

func TestTailscaleStatusOmitsCredentials(t *testing.T) {
	expiry := time.UnixMilli(1_800_000_000_000)
	status := tailscaleStatusFrom(&ipnstate.Status{
		BackendState:   ipn.Running.String(),
		TailscaleIPs:   []netip.Addr{netip.MustParseAddr("100.64.0.1")},
		CurrentTailnet: &ipnstate.TailnetStatus{Name: "user@example.com", MagicDNSSuffix: "tail1234.ts.net"},
		Self:           &ipnstate.PeerStatus{DNSName: "phone.tail1234.ts.net.", KeyExpiry: &expiry},
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			key.NewNode().Public(): testPeer("b.tail1234.ts.net.", false, "100.64.0.3"),
			key.NewNode().Public(): testPeer("a.tail1234.ts.net.", true, "100.64.0.2"),
		},
	})
	require.Equal(t, "Running", status.State)
	require.Equal(t, "tail1234.ts.net", status.MagicDNSSuffix)
	require.Equal(t, "phone.tail1234.ts.net", status.Self.Name)
	require.Equal(t, []string{"100.64.0.1"}, status.Self.Addresses)
	require.Equal(t, expiry.UnixMilli(), status.KeyExpiry)
	require.Equal(t, "a.tail1234.ts.net", status.Peers[0].Name, "online peers first")
	require.Equal(t, "b.tail1234.ts.net", status.Peers[1].Name)
}
