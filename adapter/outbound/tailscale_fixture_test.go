//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/tailnet"
	C "github.com/metacubex/mihomo/constant"
	RC "github.com/metacubex/mihomo/rules/common"
	"github.com/stretchr/testify/require"
)

// These tests run the outbound against the official Tailscale test control,
// DERP and STUN servers and a real tsnet peer (test/tailscale/fixture). They
// build that fixture with the Go toolchain, so they only run when
// MIHOMO_TAILSCALE_FIXTURE is set.

type tailscaleFixture struct {
	Control string `json:"control"`
	Admin   string `json:"admin"`
	Peer4   string `json:"peer4"`
	Peer6   string `json:"peer6"`
	Suffix  string `json:"suffix"`
}

var (
	tailscaleFixtureBuild  sync.Once
	tailscaleFixtureBinary string
	tailscaleFixtureErr    error
)

func startTailscaleFixture(t *testing.T, args ...string) tailscaleFixture {
	t.Helper()
	if os.Getenv("MIHOMO_TAILSCALE_FIXTURE") == "" {
		t.Skip("set MIHOMO_TAILSCALE_FIXTURE=1 to run against the Tailscale test control server")
	}
	tailscaleFixtureBuild.Do(func() {
		// One path reused by every run, so repeated runs leave one binary.
		dir := filepath.Join(os.TempDir(), "mihomo-tailscale-fixture")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			tailscaleFixtureErr = err
			return
		}
		tailscaleFixtureBinary = filepath.Join(dir, "fixture")
		build := exec.Command("go", "build", "-o", tailscaleFixtureBinary, ".")
		build.Dir = filepath.Join("..", "..", "test", "tailscale", "fixture")
		if output, err := build.CombinedOutput(); err != nil {
			tailscaleFixtureErr = fmt.Errorf("build the fixture: %w\n%s", err, output)
		}
	})
	require.NoError(t, tailscaleFixtureErr)

	cmd := exec.Command(tailscaleFixtureBinary, args...)
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	})

	decoded := make(chan error, 1)
	var fixture tailscaleFixture
	go func() { decoded <- json.NewDecoder(stdout).Decode(&fixture) }()
	select {
	case err := <-decoded:
		require.NoError(t, err)
	case <-time.After(time.Minute):
		t.Fatal("the fixture did not start")
	}
	return fixture
}

func (f tailscaleFixture) completeAuth(t *testing.T, authURL string) {
	t.Helper()
	response, err := http.Get(f.Admin + "/complete-auth?url=" + url.QueryEscape(authURL))
	require.NoError(t, err)
	_ = response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)
}

func useTailscaleHome(t *testing.T) {
	t.Helper()
	previous := C.Path.HomeDir()
	C.SetHomeDir(t.TempDir())
	t.Cleanup(func() { C.SetHomeDir(previous) })
}

func newFixtureTailscale(t *testing.T, fixture tailscaleFixture, name, stateDir string) *Tailscale {
	t.Helper()
	tailscale, err := NewTailscale(TailscaleOption{
		Name:       name,
		ControlURL: fixture.Control,
		StateDir:   stateDir,
		Hostname:   "flclash",
		UDP:        true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = tailscale.Close() })
	return tailscale
}

func waitTailscaleStatus(t *testing.T, ctx context.Context, tailscale *Tailscale, done func(*TailscaleStatus) bool) *TailscaleStatus {
	t.Helper()
	for {
		status, err := tailscale.Status(ctx)
		require.NoError(t, err)
		if done(status) {
			return status
		}
		select {
		case <-ctx.Done():
			t.Fatalf("status never reached the expected state, last %+v", status)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func runningWithPeer(status *TailscaleStatus) bool {
	return status.State == "Running" && len(status.Peers) > 0
}

func requireTCPEcho(t *testing.T, ctx context.Context, tailscale *Tailscale, metadata *C.Metadata) {
	t.Helper()
	conn, err := tailscale.DialContext(ctx, metadata)
	require.NoError(t, err)
	defer conn.Close()
	payload := []byte("tailnet tcp echo")
	_, err = conn.Write(payload)
	require.NoError(t, err)
	received := make([]byte, len(payload))
	_, err = io.ReadFull(conn, received)
	require.NoError(t, err)
	require.Equal(t, payload, received)
}

func requireUDPEcho(t *testing.T, ctx context.Context, tailscale *Tailscale, peer netip.Addr) {
	t.Helper()
	metadata := &C.Metadata{NetWork: C.UDP, DstIP: peer, DstPort: 8080}
	conn, err := tailscale.ListenPacketContext(ctx, metadata)
	require.NoError(t, err)
	defer conn.Close()
	payload := []byte("tailnet udp echo")
	target := net.UDPAddrFromAddrPort(netip.AddrPortFrom(peer, 8080))
	received := make([]byte, 64)
	for attempt := 0; attempt < 10; attempt++ {
		_, err = conn.WriteTo(payload, target)
		require.NoError(t, err)
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		n, _, err := conn.ReadFrom(received)
		if err == nil {
			require.Equal(t, payload, received[:n])
			return
		}
	}
	t.Fatal("no UDP echo from the peer")
}

func TestTailscaleFixtureInteractiveLogin(t *testing.T) {
	fixture := startTailscaleFixture(t, "-require-auth")
	useTailscaleHome(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	peer := netip.MustParseAddr(fixture.Peer4)

	tailscale := newFixtureTailscale(t, fixture, "Home", "tailscale-networks/interactive")
	tailscale.Warm()
	time.Sleep(200 * time.Millisecond)
	status, err := tailscale.Status(ctx)
	require.NoError(t, err)
	require.Equal(t, TailscaleIdle, status.State, "warm-up must not request a login page")

	require.NoError(t, tailscale.Login(ctx, ""))
	status = waitTailscaleStatus(t, ctx, tailscale, func(status *TailscaleStatus) bool {
		return status.AuthURL != ""
	})
	require.Equal(t, "NeedsLogin", status.State)
	fixture.completeAuth(t, status.AuthURL)

	status = waitTailscaleStatus(t, ctx, tailscale, runningWithPeer)
	require.Equal(t, fixture.Suffix, status.MagicDNSSuffix)
	require.NotEmpty(t, status.Self.Addresses)
	// One login registers one node: the peer list holds only the fixture peer.
	require.Len(t, status.Peers, 1, "%+v", status.Peers)
	require.Equal(t, "nas."+fixture.Suffix, status.Peers[0].Name)
	require.Contains(t, status.Peers[0].Addresses, fixture.Peer4)

	require.Eventually(t, func() bool {
		return tailnet.Lookup("Home").MatchAddr(peer)
	}, 30*time.Second, 100*time.Millisecond, "routes follow the network map")
	routes := tailnet.Lookup("Home")
	require.True(t, routes.MatchAddr(netip.MustParseAddr(fixture.Peer6)))
	require.True(t, routes.MatchHost("nas"))
	require.True(t, routes.MatchHost("nas."+fixture.Suffix))
	matched, adapter := RC.NewTailnet("Home", "Home").Match(&C.Metadata{DstIP: peer}, C.RuleMatchHelper{})
	require.True(t, matched)
	require.Equal(t, "Home", adapter)

	requireTCPEcho(t, ctx, tailscale, &C.Metadata{NetWork: C.TCP, DstIP: peer, DstPort: 8080})
	requireTCPEcho(t, ctx, tailscale, &C.Metadata{NetWork: C.TCP, Host: "nas." + fixture.Suffix, DstPort: 8080})
	requireUDPEcho(t, ctx, tailscale, peer)
	latency, err := tailscale.PingPeers(ctx)
	require.NoError(t, err)
	require.Greater(t, latency, time.Duration(0))

	// A re-parsed outbound with the same options shares the running session.
	reparsed := newFixtureTailscale(t, fixture, "Home", "tailscale-networks/interactive")
	require.NoError(t, tailscale.Close())
	requireTCPEcho(t, ctx, reparsed, &C.Metadata{NetWork: C.TCP, DstIP: peer, DstPort: 8080})
	status, err = reparsed.Status(ctx)
	require.NoError(t, err)
	require.Equal(t, "Running", status.State)
	selfAddress := status.Self.Addresses[0]

	// Once nothing uses the session it stops; the saved login brings a later
	// config's outbound up by itself, without a login page.
	previousLinger := tailscaleSessionLinger
	tailscaleSessionLinger = 50 * time.Millisecond
	t.Cleanup(func() { tailscaleSessionLinger = previousLinger })
	stateDir := C.Path.Resolve("tailscale-networks/interactive")
	require.NoError(t, reparsed.Close())
	require.Eventually(t, func() bool {
		return tailscaleSessions.peek(stateDir, reparsed.sessionKey) == nil
	}, 5*time.Second, 20*time.Millisecond, "an unused session stops after the linger")
	restarted := newFixtureTailscale(t, fixture, "Home", "tailscale-networks/interactive")
	restarted.Warm()
	status = waitTailscaleStatus(t, ctx, restarted, runningWithPeer)
	require.Equal(t, selfAddress, status.Self.Addresses[0])
	requireTCPEcho(t, ctx, restarted, &C.Metadata{NetWork: C.TCP, DstIP: peer, DstPort: 8080})

	// Logging out resets tsnet to the default control server; the next login
	// must still go to the configured one.
	require.NoError(t, restarted.Logout(ctx))
	status, err = restarted.Status(ctx)
	require.NoError(t, err)
	require.Equal(t, TailscaleIdle, status.State)
	require.Nil(t, tailnet.Lookup("Home"))
	require.ErrorIs(t, restarted.Logout(ctx), errTailscaleNotRunning)
	require.NoError(t, restarted.Login(ctx, ""))
	status = waitTailscaleStatus(t, ctx, restarted, func(status *TailscaleStatus) bool {
		return status.AuthURL != ""
	})
	require.True(t, strings.HasPrefix(status.AuthURL, fixture.Control), status.AuthURL)
	fixture.completeAuth(t, status.AuthURL)
	waitTailscaleStatus(t, ctx, restarted, runningWithPeer)

	require.NoError(t, ForgetTailscaleState("tailscale-networks/interactive"))
	_, err = os.Stat(stateDir)
	require.True(t, os.IsNotExist(err))
	_, err = restarted.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: peer, DstPort: 8080})
	require.ErrorIs(t, err, errTailscaleRemoved)
}

func TestTailscaleFixtureAuthKeyAfterInteractiveStart(t *testing.T) {
	const authKey = "tskey-auth-fixture"
	fixture := startTailscaleFixture(t, "-auth-key", authKey)
	useTailscaleHome(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	peer := netip.MustParseAddr(fixture.Peer4)

	// A session started without the key, for example by a delay test, is
	// replaced so that the key reaches control.
	office := newFixtureTailscale(t, fixture, "Office", "tailscale-networks/key")
	require.NoError(t, office.Login(ctx, ""))
	waitTailscaleStatus(t, ctx, office, func(status *TailscaleStatus) bool {
		return slices.ContainsFunc(status.Health, func(message string) bool {
			return strings.Contains(message, "invalid authkey")
		})
	})
	require.NoError(t, office.Login(ctx, authKey))
	waitTailscaleStatus(t, ctx, office, runningWithPeer)
	requireTCPEcho(t, ctx, office, &C.Metadata{NetWork: C.TCP, DstIP: peer, DstPort: 8080})
}
