package adapter

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
)

type flightTestAdapter struct {
	*outbound.Base
	release chan struct{}
	calls   atomic.Int32
}

func (a *flightTestAdapter) DialContext(ctx context.Context, _ *C.Metadata) (C.Conn, error) {
	a.calls.Add(1)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-a.release:
	}
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		if _, err := http.ReadRequest(bufio.NewReader(server)); err == nil {
			time.Sleep(time.Millisecond)
			fmt.Fprint(server, "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
		}
	}()
	return outbound.NewConn(client, a), nil
}

func newFlightTestProxy() (*Proxy, *flightTestAdapter) {
	a := &flightTestAdapter{Base: outbound.NewBase(outbound.BaseOption{Name: "test", Type: C.Direct}), release: make(chan struct{})}
	return NewProxy(a), a
}

func TestURLTestSharesConcurrentWorkAndPublishesOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, a := newFlightTestProxy()
		results := make(chan error, 20)
		began := time.Now()
		for range 20 {
			go func() { _, err := p.URLTest(context.Background(), "http://probe.test/", nil); results <- err }()
		}
		synctest.Wait()
		if got := a.calls.Load(); got != 1 {
			t.Fatalf("concurrent identical probes dialed %d times", got)
		}
		close(a.release)
		for range 20 {
			if err := <-results; err != nil {
				t.Fatal(err)
			}
		}
		if history := p.DelayHistory(); len(history) != 1 {
			t.Fatalf("shared result published %d times", len(history))
		}
		if !p.URLTestSucceededSince("http://probe.test/", "*", time.Second, began) {
			t.Fatal("fresh success was not reusable")
		}
		if p.URLTestSucceededSince("http://probe.test/", "200", time.Second, began) || p.URLTestSucceededSince("http://probe.test/", "*", time.Second, time.Now().Add(time.Second)) {
			t.Fatal("different status or obsolete round reused a result")
		}
		if _, err := p.URLTest(context.Background(), "http://probe.test/", nil); err != nil {
			t.Fatal(err)
		}
		if a.calls.Load() != 2 {
			t.Fatal("finished flight became a stale result cache")
		}
	})
}

func TestURLTestWaiterCancellationKeepsLeaderAlive(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, a := newFlightTestProxy()
		leader := make(chan error, 1)
		go func() { _, err := p.URLTest(context.Background(), "http://probe.test/", nil); leader <- err }()
		synctest.Wait()
		ctx, cancel := context.WithCancel(context.Background())
		waiter := make(chan error, 1)
		go func() { _, err := p.URLTest(ctx, "http://probe.test/", nil); waiter <- err }()
		synctest.Wait()
		cancel()
		if err := <-waiter; !errors.Is(err, context.Canceled) {
			t.Fatalf("waiter = %v", err)
		}
		if len(p.DelayHistory()) != 0 {
			t.Fatal("canceled waiter changed node health")
		}
		close(a.release)
		if err := <-leader; err != nil {
			t.Fatal(err)
		}
		if a.calls.Load() != 1 || !p.AliveForTestUrl("http://probe.test/") {
			t.Fatal("waiter canceled the shared connection")
		}
	})
}

func TestURLTestWaiterRetriesAbandonedOrShorterProbe(t *testing.T) {
	for _, timedOut := range []bool{false, true} {
		t.Run(fmt.Sprint(timedOut), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p, a := newFlightTestProxy()
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				leader, waiter := make(chan error, 1), make(chan error, 1)
				go func() { _, err := p.URLTest(ctx, "http://probe.test/", nil); leader <- err }()
				synctest.Wait()
				go func() { _, err := p.URLTest(context.Background(), "http://probe.test/", nil); waiter <- err }()
				synctest.Wait()
				if timedOut {
					time.Sleep(time.Second)
				} else {
					cancel()
				}
				if err := <-leader; err == nil {
					t.Fatal("leader unexpectedly succeeded")
				}
				synctest.Wait()
				if a.calls.Load() != 2 {
					t.Fatal("waiting caller inherited another caller's deadline")
				}
				close(a.release)
				if err := <-waiter; err != nil {
					t.Fatal(err)
				}
				if !p.AliveForTestUrl("http://probe.test/") {
					t.Fatal("retry did not restore health")
				}
			})
		})
	}
}

func TestURLTestSeparatesStatusURLClassAndGroups(t *testing.T) {
	for _, group := range []bool{false, true} {
		t.Run(fmt.Sprint(group), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p, a := newFlightTestProxy()
				if group {
					a.Base = outbound.NewBase(outbound.BaseOption{Name: "group", Type: C.Selector})
				}
				results := make(chan error, 4)
				expected, _ := utils.NewUnsignedRanges[uint16]("204")
				contexts := []context.Context{context.Background(), context.Background(), WithBackgroundURLTest(context.Background()), context.Background()}
				urls := []string{"http://probe.test/", "http://probe.test/", "http://probe.test/", "http://probe.test/other"}
				for i := range 4 {
					go func() {
						var statuses utils.IntRanges[uint16]
						if i == 1 && !group {
							statuses = expected
						}
						_, err := p.URLTest(contexts[i], urls[i], statuses)
						results <- err
					}()
				}
				synctest.Wait()
				if a.calls.Load() != 4 {
					t.Fatal("incompatible probes were merged")
				}
				close(a.release)
				for range 4 {
					if err := <-results; err != nil {
						t.Fatal(err)
					}
				}
			})
		})
	}
}
