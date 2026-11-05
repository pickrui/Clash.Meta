package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

type providerJSONWriter func([]byte) (int, error)

func (w providerJSONWriter) Write(data []byte) (int, error) { return w(data) }

func inlineJSONFixture(t *testing.T, nodes []C.Proxy) *InlineProvider {
	t.Helper()
	p, err := NewInlineProvider("inline <&>", nil, func([]byte) ([]C.Proxy, error) { return nodes, nil }, NewHealthCheck(nil, "", 0, 0, true, nil))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, p.Close()) })
	return p
}

func TestProviderJSONKeepsEmptyListsAndEncodingErrors(t *testing.T) {
	p := inlineJSONFixture(t, nil)
	for _, nodes := range [][]C.Proxy{nil, {}, {adapter.NewProxy(outbound.NewDirect())}} {
		p.setProxies(nodes)
		var got bytes.Buffer
		want, err := json.Marshal(p)
		require.NoError(t, err)
		require.NoError(t, WriteJSON(context.Background(), &got, p))
		require.Equal(t, string(want), got.String())
	}
	p.updateAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	_, wantErr := json.Marshal(p)
	var got bytes.Buffer
	err := WriteJSON(context.Background(), &got, p)
	require.EqualError(t, err, wantErr.Error())
	require.Zero(t, got.Len())
}

func TestProviderJSONSnapshotDoesNotHoldUpdatesDuringWrites(t *testing.T) {
	old := []C.Proxy{adapter.NewProxy(outbound.NewDirect()), adapter.NewProxy(outbound.NewReject())}
	p := inlineJSONFixture(t, old)
	want, err := json.Marshal(p)
	require.NoError(t, err)
	entered, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	var once sync.Once
	var got bytes.Buffer
	finished := make(chan error, 1)
	go func() {
		finished <- WriteJSON(context.Background(), providerJSONWriter(func(data []byte) (int, error) {
			once.Do(func() {
				close(entered)
				<-release
			})
			return got.Write(data)
		}), p)
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("response did not reach writer")
	}
	updated := make(chan struct{})
	go func() {
		p.setProxies([]C.Proxy{old[1]})
		_ = p.Update()
		close(updated)
	}()
	select {
	case <-updated:
	case <-time.After(3 * time.Second):
		t.Fatal("slow reader blocked provider update")
	}
	release <- struct{}{}
	select {
	case err := <-finished:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("response did not complete")
	}
	require.Equal(t, string(want), got.String())
	got.Reset()
	require.NoError(t, WriteJSON(context.Background(), &got, p))
	want, err = json.Marshal(p)
	require.NoError(t, err)
	require.Equal(t, string(want), got.String())
}

func TestProviderJSONConcurrentInlineUpdates(t *testing.T) {
	nodes := []C.Proxy{adapter.NewProxy(outbound.NewDirect()), adapter.NewProxy(outbound.NewReject())}
	p := inlineJSONFixture(t, nodes)
	var group sync.WaitGroup
	group.Go(func() {
		for i := range 100 {
			p.setProxies(nodes[i%2:])
			if err := p.Update(); err != nil {
				t.Error(err)
			}
		}
	})
	for range 4 {
		group.Go(func() {
			for range 100 {
				var got bytes.Buffer
				if err := WriteJSON(context.Background(), &got, p); err != nil {
					t.Error(err)
				}
				if !json.Valid(got.Bytes()) {
					t.Error("invalid concurrent provider response")
				}
				if _, err := json.Marshal(p); err != nil {
					t.Error(err)
				}
			}
		})
	}
	group.Wait()
}
