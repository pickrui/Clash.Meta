package provider

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

type dialerTestProxy struct {
	C.Proxy
	name   string
	typ    C.AdapterType
	closed atomic.Int32
}

func (p *dialerTestProxy) Name() string        { return p.name }
func (p *dialerTestProxy) Type() C.AdapterType { return p.typ }
func (p *dialerTestProxy) Close() error        { p.closed.Add(1); return nil }

type cloneableDialerTestProxy struct {
	*dialerTestProxy
	derived C.Proxy
}

func (p *cloneableDialerTestProxy) WithDialerProxy(string) (C.Proxy, error) {
	return p.derived, nil
}

type dialerTestProvider struct {
	P.ProxyProvider
	proxies []C.Proxy
	version uint32
}

func (p *dialerTestProvider) Proxies() []C.Proxy { return p.proxies }
func (p *dialerTestProvider) Version() uint32    { return p.version }

func TestNewDialerProviderClosesOnlyOwnedMembersOnFailure(t *testing.T) {
	owned := &dialerTestProxy{name: "derived", typ: C.Http}
	original := &cloneableDialerTestProxy{
		dialerTestProxy: &dialerTestProxy{name: "original", typ: C.Http},
		derived:         owned,
	}
	shared := &dialerTestProxy{name: "nested group", typ: C.Selector}
	unsupported := &dialerTestProxy{name: "unsupported", typ: C.Dns}
	source := &dialerTestProvider{proxies: []C.Proxy{original, shared, unsupported}}

	if _, err := NewDialerProvider(source, "entry", "", "", 0, 0, false, nil); err == nil {
		t.Fatal("expected unsupported member error")
	}
	if owned.closed.Load() != 1 {
		t.Fatalf("owned clone close count = %d", owned.closed.Load())
	}
	if original.closed.Load() != 0 {
		t.Fatalf("source member close count = %d", original.closed.Load())
	}
	if shared.closed.Load() != 0 {
		t.Fatalf("shared member close count = %d", shared.closed.Load())
	}
}

type dialerTestStream struct {
	*outbound.Base
	conn net.Conn
}

func (p *dialerTestStream) DialContext(context.Context, *C.Metadata) (C.Conn, error) {
	return outbound.NewConn(p.conn, p), nil
}

func (p *dialerTestStream) Close() error { return p.conn.Close() }

func TestDialerProviderRetainsActiveStreams(t *testing.T) {
	for _, operation := range []string{"refresh", "close"} {
		t.Run(operation, func(t *testing.T) {
			client, server := net.Pipe()
			defer server.Close()
			go func() { _, _ = io.Copy(server, server) }()
			derived := adapter.NewProxy(outbound.NewAutoCloseProxyAdapter(&dialerTestStream{
				Base: outbound.NewBase(outbound.BaseOption{Name: "derived", Type: C.Http}),
				conn: client,
			}))
			defer derived.Close()
			original := &cloneableDialerTestProxy{
				dialerTestProxy: &dialerTestProxy{name: "source", typ: C.Http},
				derived:         derived,
			}
			shared := &dialerTestProxy{name: "nested group", typ: C.Selector}
			source := &dialerTestProvider{proxies: []C.Proxy{original, shared}, version: 1}
			provider, err := NewDialerProvider(source, "entry", "", "", 0, 0, false, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer provider.Close()
			conn, err := provider.Proxies()[0].DialContext(context.Background(), &C.Metadata{})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if operation == "refresh" {
				source.proxies = []C.Proxy{shared}
				source.version++
				provider.Proxies()
			} else {
				_ = provider.Close()
			}
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			if _, err := conn.Write([]byte("alive")); err != nil {
				t.Fatal(err)
			}
			data := make([]byte, 5)
			if _, err := io.ReadFull(conn, data); err != nil {
				t.Fatal(err)
			}
			if string(data) != "alive" || original.closed.Load() != 0 || shared.closed.Load() != 0 {
				t.Fatal("provider retired an active or shared member")
			}
		})
	}
}
