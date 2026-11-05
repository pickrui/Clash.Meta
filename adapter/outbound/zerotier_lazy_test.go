//go:build !no_zerotier

package outbound

import (
	"os"
	"sync"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	ZT "github.com/metacubex/zerotier-go"
	"github.com/stretchr/testify/require"
)

func TestZeroTierUnusedAndClosedNodesKeepNoFrameQueue(t *testing.T) {
	previousHome := C.Path.HomeDir()
	C.SetHomeDir(t.TempDir())
	t.Cleanup(func() { C.SetHomeDir(previousHome) })
	node, err := NewZeroTier(ZeroTierOption{Name: "unused", Network: "8056c2e21c000001"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = node.Close() })
	require.Nil(t, node.frameCh)
	_, err = os.Stat(node.option.StateDir)
	require.ErrorIs(t, err, os.ErrNotExist)
	require.NoError(t, node.Close())
	require.ErrorIs(t, node.start(), errZeroTierClosed)
	require.Nil(t, node.frameCh)
	_, err = os.Stat(node.option.StateDir)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestZeroTierFrameQueueSurvivesStartupRetryAndIdentityRecovery(t *testing.T) {
	previousHome := C.Path.HomeDir()
	C.SetHomeDir(t.TempDir())
	t.Cleanup(func() { C.SetHomeDir(previousHome) })
	node, err := NewZeroTier(ZeroTierOption{
		Name: "offline", Network: "8056c2e21c000001", BasicOption: BasicOption{DialerProxy: "offline"},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = node.Close() })
	node.dialer = zeroTierOfflineDialer{}
	store := ZT.NewMemoryStore()
	require.NoError(t, store.Put("identity.secret", []byte("corrupt-fixture-state")))
	node.stateStore = store
	require.Error(t, node.start())
	require.Nil(t, node.runtime)
	queue := node.frameCh
	require.Equal(t, zeroTierFrameQueueSize, cap(queue))
	require.NoError(t, store.Delete("identity.secret"))
	var starts sync.WaitGroup
	for range 8 {
		starts.Go(func() {
			if err := node.start(); err != nil {
				t.Errorf("start: %v", err)
			}
		})
	}
	starts.Wait()
	require.NotNil(t, node.runtime)
	require.Equal(t, queue, node.frameCh)
	runtime := node.runtime
	node.recoverIdentityCollision(runtime, runtime.nodeAddress)
	require.NotNil(t, node.runtime)
	require.NotSame(t, runtime, node.runtime)
	require.Equal(t, queue, node.frameCh)
	require.NoError(t, node.Close())
	require.ErrorIs(t, node.start(), errZeroTierClosed)
}

func BenchmarkZeroTierUnused(b *testing.B) {
	previousHome := C.Path.HomeDir()
	C.SetHomeDir(b.TempDir())
	b.Cleanup(func() { C.SetHomeDir(previousHome) })
	option := ZeroTierOption{Name: "unused", Network: "8056c2e21c000001"}
	b.ReportAllocs()
	for b.Loop() {
		node, err := NewZeroTier(option)
		if err != nil {
			b.Fatal(err)
		}
		if err := node.Close(); err != nil {
			b.Fatal(err)
		}
	}
}
