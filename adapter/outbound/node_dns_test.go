package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
	D "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func nodeDNSOwner(node C.ProxyAdapter) *nodeDNS {
	switch node := node.(type) {
	case *WireGuard:
		return node.resolver
	case *Masque:
		return node.resolver
	default:
		panic("unexpected test node")
	}
}

func TestNodeDNSConstructionAndTerminalClose(t *testing.T) {
	for _, factory := range nodeDNSFactories(t) {
		t.Run(factory.name, func(t *testing.T) {
			_, err := factory.new([]string{"https://[malformed"})
			require.Error(t, err)
			for _, servers := range [][]string{nil, {"192.0.2.53"}} {
				node, err := factory.new(servers)
				require.NoError(t, err)
				t.Cleanup(func() { _ = node.Close() })
				owner := nodeDNSOwner(node)
				if len(servers) == 0 {
					require.Nil(t, owner)
					continue
				}
				require.Nil(t, owner.current)
				require.Same(t, node, owner.servers[0].ProxyAdapter)
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				_, err = owner.get(ctx)
				require.ErrorIs(t, err, context.Canceled)
				require.Nil(t, owner.current)
				require.NoError(t, node.Close())
				require.NoError(t, node.Close())
				require.Nil(t, owner.servers)
				_, err = owner.get(context.Background())
				require.ErrorIs(t, err, net.ErrClosed)
				require.Nil(t, owner.current)
			}
		})
	}
}

func TestNodeDNSConcurrentCreationAndClose(t *testing.T) {
	for _, raceClose := range []bool{false, true} {
		t.Run(fmt.Sprint(raceClose), func(t *testing.T) {
			owner := &nodeDNS{servers: []dns.NameServer{{Net: "rcode", Addr: "success"}}}
			t.Cleanup(owner.close)
			var workers sync.WaitGroup
			instances := make(chan resolver.Resolver, 64)
			for range 64 {
				workers.Go(func() {
					r, err := owner.get(context.Background())
					if err == nil {
						instances <- r
					} else if !raceClose || !errors.Is(err, net.ErrClosed) {
						t.Errorf("first use: %v", err)
					}
				})
				if raceClose {
					workers.Go(owner.close)
				}
			}
			workers.Wait()
			close(instances)
			owner.close()
			var first resolver.Resolver
			for r := range instances {
				if first == nil {
					first = r
				}
				require.Same(t, first, r)
				_, err := r.ExchangeContext(context.Background(), new(D.Msg).SetQuestion("closed.test.", D.TypeA))
				require.ErrorIs(t, err, context.Canceled)
			}
			if !raceClose {
				require.NotNil(t, first)
			}
			require.Nil(t, owner.current)
			require.Nil(t, owner.servers)
			_, err := owner.get(context.Background())
			require.ErrorIs(t, err, net.ErrClosed)
		})
	}
}

type nodeDNSProxy struct {
	*Base
	blocked bool
	started chan context.Context
	calls   atomic.Int32
	workers sync.WaitGroup
}

func (p *nodeDNSProxy) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if metadata.RemoteAddress() != "127.0.0.1:0" {
		return nil, fmt.Errorf("unexpected DNS route: %s", metadata.RemoteAddress())
	}
	p.calls.Add(1)
	if p.blocked {
		p.started <- ctx
		<-ctx.Done()
		return nil, ctx.Err()
	}
	client, server := net.Pipe()
	p.workers.Go(func() {
		defer server.Close()
		conn := &D.Conn{Conn: server}
		query, err := conn.ReadMsg()
		if err != nil {
			return
		}
		reply := new(D.Msg).SetReply(query)
		header := D.RR_Header{Name: query.Question[0].Name, Rrtype: query.Question[0].Qtype, Class: D.ClassINET, Ttl: 60}
		if header.Rrtype == D.TypeA {
			reply.Answer = []D.RR{&D.A{Hdr: header, A: net.ParseIP("192.0.2.1").To4()}}
		} else {
			reply.Answer = []D.RR{&D.AAAA{Hdr: header, AAAA: net.ParseIP("2001:db8::1")}}
		}
		_ = conn.WriteMsg(reply)
	})
	return NewConn(client, p), nil
}

func TestNodeCloseCancelsPrivateDNS(t *testing.T) {
	for _, factory := range nodeDNSFactories(t) {
		t.Run(factory.name, func(t *testing.T) {
			node, err := factory.new([]string{"tcp://127.0.0.1:0"})
			require.NoError(t, err)
			t.Cleanup(func() { _ = node.Close() })
			proxy := &nodeDNSProxy{Base: NewBase(BaseOption{Name: "blocked-dns"}), blocked: true, started: make(chan context.Context, 1)}
			owner := nodeDNSOwner(node)
			owner.servers[0].ProxyAdapter = proxy
			r, err := owner.get(context.Background())
			require.NoError(t, err)
			done := make(chan error, 1)
			go func() {
				_, err := r.LookupIPv4(context.Background(), "blocked.test")
				done <- err
			}()
			var upstream context.Context
			select {
			case upstream = <-proxy.started:
			case <-time.After(time.Second):
				t.Fatal("private DNS did not start")
			}
			require.NoError(t, node.Close())
			require.ErrorIs(t, upstream.Err(), context.Canceled)
			select {
			case err := <-done:
				require.ErrorIs(t, err, context.Canceled)
			case <-time.After(time.Second):
				t.Fatal("private DNS survived node close")
			}
			_, err = r.LookupIPv4(context.Background(), "late.test")
			require.ErrorIs(t, err, context.Canceled)
			require.EqualValues(t, 1, proxy.calls.Load())
			require.Nil(t, owner.current)
		})
	}
}

func TestNodeDNSPreservesRoutingCacheAndFamily(t *testing.T) {
	proxy := &nodeDNSProxy{Base: NewBase(BaseOption{Name: "dns-fixture"})}
	owner := &nodeDNS{ipv6: true, servers: []dns.NameServer{{Net: "tcp", Addr: "127.0.0.1:0", ProxyAdapter: proxy}}}
	t.Cleanup(func() { owner.close(); proxy.workers.Wait() })
	r, err := owner.get(context.Background())
	require.NoError(t, err)
	for range 2 {
		ips, err := r.LookupIPv4(context.Background(), "cached.test")
		require.NoError(t, err)
		require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, ips)
	}
	ips, err := r.LookupIPv6(context.Background(), "cached.test")
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("2001:db8::1")}, ips)
	require.EqualValues(t, 2, proxy.calls.Load())
	r.ResetConnection()
	again, err := owner.get(context.Background())
	require.NoError(t, err)
	require.Same(t, r, again)
	r.ClearCache()
	_, err = r.LookupIPv4(context.Background(), "cached.test")
	require.NoError(t, err)
	require.EqualValues(t, 3, proxy.calls.Load())
	owner.close()
	_, err = owner.get(context.Background())
	require.ErrorIs(t, err, net.ErrClosed)

	previous := resolver.DefaultResolver
	global := dns.NewResolver(dns.Config{Main: []dns.NameServer{{Net: "rcode", Addr: "success"}}})
	resolver.DefaultResolver = global
	t.Cleanup(func() { resolver.DefaultResolver = previous; global.CloseQueries() })
	var none *nodeDNS
	none.close()
	fallback, err := none.get(context.Background())
	require.NoError(t, err)
	require.Equal(t, resolver.DefaultResolver, fallback)
	_, err = fallback.ExchangeContext(context.Background(), new(D.Msg).SetQuestion("global.test.", D.TypeA))
	require.NoError(t, err)
	_, err = owner.get(context.Background())
	require.ErrorIs(t, err, net.ErrClosed)
}
