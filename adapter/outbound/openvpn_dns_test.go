package outbound

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/dns"
	ovpn "github.com/metacubex/mihomo/transport/openvpn"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/semaphore"
)

func blockedSessionDNS(t *testing.T) (*nodeDNS, resolver.Resolver, func()) {
	t.Helper()
	const queries = 32
	proxy := &nodeDNSProxy{Base: NewBase(BaseOption{Name: "blocked-session-dns"}), blocked: true, started: make(chan context.Context, queries)}
	owner := &nodeDNS{servers: []dns.NameServer{{Net: "tcp", Addr: "127.0.0.1:0", ProxyAdapter: proxy}}}
	r, err := owner.get(context.Background())
	require.NoError(t, err)
	var workers sync.WaitGroup
	results := make(chan error, queries)
	for i := range queries {
		workers.Go(func() {
			_, err := r.LookupIPv4(context.Background(), fmt.Sprintf("pending-%d.test", i))
			results <- err
		})
	}
	t.Cleanup(func() { owner.close(); workers.Wait() })
	contexts := make([]context.Context, queries)
	for i := range contexts {
		select {
		case contexts[i] = <-proxy.started:
		case <-time.After(time.Second):
			t.Fatal("private DNS query did not start")
		}
	}
	return owner, r, func() {
		t.Helper()
		for _, ctx := range contexts {
			require.ErrorIs(t, ctx.Err(), context.Canceled)
		}
		for range queries {
			select {
			case err := <-results:
				require.ErrorIs(t, err, context.Canceled)
			case <-time.After(time.Second):
				t.Fatal("retired session retained DNS work")
			}
		}
		_, err := r.LookupIPv4(context.Background(), "late.test")
		require.ErrorIs(t, err, context.Canceled)
		require.EqualValues(t, queries, proxy.calls.Load())
	}
}

type sessionDNSStack struct {
	ipStack
	closed chan struct{}
	once   sync.Once
}

func (s *sessionDNSStack) Read([][]byte, []int, int) (int, error) {
	<-s.closed
	return 0, net.ErrClosed
}

func (s *sessionDNSStack) Close() error {
	s.once.Do(func() { close(s.closed) })
	return nil
}

func openVPNDNSFixture(t *testing.T) (*OpenVPN, net.Conn) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	local, peer := net.Pipe()
	config := &ovpn.ClientConfig{Proto: ovpn.ProtoTCP}
	client, err := ovpn.NewClient(config, ovpn.NewTCPPacketIO(local))
	require.NoError(t, err)
	node := &OpenVPN{
		Base: NewBase(BaseOption{Name: "session-fixture"}), config: config,
		option: &OpenVPNOption{}, client: client, running: true,
		tunDevice: &sessionDNSStack{closed: make(chan struct{})},
		runCtx:    ctx, runCancel: cancel, runLock: semaphore.NewWeighted(1),
	}
	t.Cleanup(func() { _ = node.Close(); _ = peer.Close() })
	return node, peer
}

func TestOpenVPNSessionRetiresPrivateDNS(t *testing.T) {
	for _, terminal := range []bool{false, true} {
		t.Run(fmt.Sprint(terminal), func(t *testing.T) {
			node, peer := openVPNDNSFixture(t)
			_, r, assertRetired := blockedSessionDNS(t)
			node.resolver = r
			node.startPacketLoops()
			start := time.Now()
			if terminal {
				require.NoError(t, node.Close())
			} else {
				require.NoError(t, peer.Close())
			}
			require.Eventually(t, func() bool {
				_ = node.runLock.Acquire(context.Background(), 1)
				defer node.runLock.Release(1)
				return !node.running && node.resolver == nil
			}, time.Second, time.Millisecond)
			assertRetired()
			t.Logf("retired 32 DNS queries in %s", time.Since(start))
		})
	}
}

func TestOpenVPNLateSessionCleanupKeepsReplacementDNS(t *testing.T) {
	node, _ := openVPNDNSFixture(t)
	_, oldResolver, assertRetired := blockedSessionDNS(t)
	oldClient, oldDevice := node.client, node.tunDevice
	next := dns.NewResolver(dns.Config{Main: []dns.NameServer{{Net: "rcode", Addr: "success"}}})
	t.Cleanup(next.CloseQueries)
	node.resolver = next
	node.client = &ovpn.Client{}
	node.tunDevice = &sessionDNSStack{closed: make(chan struct{})}
	node.stopSession(oldClient, oldDevice, oldResolver)
	assertRetired()
	require.Equal(t, next, node.resolver)
	require.True(t, node.running)
	_, err := next.LookupIPv4(context.Background(), "new-session.test")
	require.ErrorIs(t, err, resolver.ErrIPNotFound)
}
