package fakeip

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/profile/cachefile"

	"github.com/metacubex/bbolt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createPools(t *testing.T, options Options) []*Pool {
	t.Helper()
	pool, err := New(options)
	require.NoError(t, err)
	filePool, _ := createCachefileStore(t, options, filepath.Join(t.TempDir(), "cache.db"))
	return []*Pool{pool, filePool}
}

func createCachefileStore(t *testing.T, options Options, path string) (*Pool, *bbolt.DB) {
	t.Helper()
	options.Persistence = false
	pool, err := New(options)
	require.NoError(t, err)
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: time.Second, NoStatistics: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	pool.store = newCachefileStore(&cachefile.CacheFile{DB: db}, options.IPNet)
	pool.restoreState()
	return pool, db
}

func TestPool_Basic(t *testing.T) {
	ipnet := netip.MustParsePrefix("192.168.0.0/28")
	pools := createPools(t, Options{
		IPNet: ipnet,
		Size:  10,
	})

	for _, pool := range pools {
		first := pool.Lookup("foo.com")
		last := pool.Lookup("bar.com")
		bar, exist := pool.LookBack(last)

		assert.Equal(t, first, netip.AddrFrom4([4]byte{192, 168, 0, 4}))
		assert.Equal(t, pool.Lookup("foo.com"), netip.AddrFrom4([4]byte{192, 168, 0, 4}))
		assert.Equal(t, last, netip.AddrFrom4([4]byte{192, 168, 0, 5}))
		assert.True(t, exist)
		assert.Equal(t, bar, "bar.com")
		assert.Equal(t, pool.Gateway(), netip.AddrFrom4([4]byte{192, 168, 0, 1}))
		assert.Equal(t, pool.Broadcast(), netip.AddrFrom4([4]byte{192, 168, 0, 15}))
		assert.Equal(t, pool.IPNet().String(), ipnet.String())
		assert.True(t, pool.Exist(netip.AddrFrom4([4]byte{192, 168, 0, 5})))
		assert.False(t, pool.Exist(netip.AddrFrom4([4]byte{192, 168, 0, 6})))
		assert.False(t, pool.Exist(netip.MustParseAddr("::1")))
	}
}

func TestPool_BasicV6(t *testing.T) {
	ipnet := netip.MustParsePrefix("2001:4860:4860::8888/118")
	pools := createPools(t, Options{
		IPNet: ipnet,
		Size:  10,
	})

	for _, pool := range pools {
		first := pool.Lookup("foo.com")
		last := pool.Lookup("bar.com")
		bar, exist := pool.LookBack(last)

		assert.Equal(t, first, netip.MustParseAddr("2001:4860:4860:0000:0000:0000:0000:8804"))
		assert.Equal(t, pool.Lookup("foo.com"), netip.MustParseAddr("2001:4860:4860:0000:0000:0000:0000:8804"))
		assert.Equal(t, last, netip.MustParseAddr("2001:4860:4860:0000:0000:0000:0000:8805"))
		assert.True(t, exist)
		assert.Equal(t, bar, "bar.com")
		assert.Equal(t, pool.Gateway(), netip.MustParseAddr("2001:4860:4860:0000:0000:0000:0000:8801"))
		assert.Equal(t, pool.Broadcast(), netip.MustParseAddr("2001:4860:4860:0000:0000:0000:0000:8bff"))
		assert.Equal(t, pool.IPNet().String(), ipnet.String())
		assert.True(t, pool.Exist(netip.MustParseAddr("2001:4860:4860:0000:0000:0000:0000:8805")))
		assert.False(t, pool.Exist(netip.MustParseAddr("2001:4860:4860:0000:0000:0000:0000:8806")))
		assert.False(t, pool.Exist(netip.MustParseAddr("127.0.0.1")))
	}
}

func TestPool_Case_Insensitive(t *testing.T) {
	ipnet := netip.MustParsePrefix("192.168.0.1/29")
	pools := createPools(t, Options{
		IPNet: ipnet,
		Size:  10,
	})

	for _, pool := range pools {
		first := pool.Lookup("foo.com")
		last := pool.Lookup("Foo.Com")
		foo, exist := pool.LookBack(last)

		assert.Equal(t, first, pool.Lookup("Foo.Com"))
		assert.Equal(t, pool.Lookup("fOo.cOM"), first)
		assert.True(t, exist)
		assert.Equal(t, foo, "foo.com")
	}
}

func TestPool_CycleUsed(t *testing.T) {
	ipnet := netip.MustParsePrefix("192.168.0.16/28")
	pools := createPools(t, Options{
		IPNet: ipnet,
		Size:  10,
	})

	for _, pool := range pools {
		foo := pool.Lookup("foo.com")
		bar := pool.Lookup("bar.com")
		for i := 0; i < 9; i++ {
			pool.Lookup(fmt.Sprintf("%d.com", i))
		}
		baz := pool.Lookup("baz.com")
		next := pool.Lookup("foo.com")
		assert.Equal(t, foo, baz)
		assert.Equal(t, next, bar)
	}
}

func TestPool_MaxCacheSize(t *testing.T) {
	ipnet := netip.MustParsePrefix("192.168.0.1/24")
	pool, _ := New(Options{
		IPNet: ipnet,
		Size:  2,
	})

	first := pool.Lookup("foo.com")
	pool.Lookup("bar.com")
	pool.Lookup("baz.com")
	next := pool.Lookup("foo.com")

	assert.NotEqual(t, first, next)
}

func TestPool_DoubleMapping(t *testing.T) {
	ipnet := netip.MustParsePrefix("192.168.0.1/24")
	pool, _ := New(Options{
		IPNet: ipnet,
		Size:  2,
	})

	// fill cache
	fooIP := pool.Lookup("foo.com")
	bazIP := pool.Lookup("baz.com")

	// make foo.com hot
	pool.Lookup("foo.com")

	// should drop baz.com
	barIP := pool.Lookup("bar.com")

	_, fooExist := pool.LookBack(fooIP)
	_, bazExist := pool.LookBack(bazIP)
	_, barExist := pool.LookBack(barIP)

	newBazIP := pool.Lookup("baz.com")

	assert.True(t, fooExist)
	assert.False(t, bazExist)
	assert.True(t, barExist)

	assert.NotEqual(t, bazIP, newBazIP)
}

func TestPool_Clone(t *testing.T) {
	ipnet := netip.MustParsePrefix("192.168.0.1/24")
	pool, _ := New(Options{
		IPNet: ipnet,
		Size:  2,
	})

	first := pool.Lookup("foo.com")
	last := pool.Lookup("bar.com")
	assert.Equal(t, first, netip.AddrFrom4([4]byte{192, 168, 0, 4}))
	assert.Equal(t, last, netip.AddrFrom4([4]byte{192, 168, 0, 5}))

	newPool, _ := New(Options{
		IPNet: ipnet,
		Size:  2,
	})
	newPool.CloneFrom(pool)
	_, firstExist := newPool.LookBack(first)
	_, lastExist := newPool.LookBack(last)
	assert.True(t, firstExist)
	assert.True(t, lastExist)
}

func TestPool_CloneKeepsAllocationState(t *testing.T) {
	ipnet := netip.MustParsePrefix("192.168.0.1/24")
	pool, _ := New(Options{
		IPNet: ipnet,
		Size:  10,
	})

	foo := pool.Lookup("foo.com")
	bar := pool.Lookup("bar.com")

	newPool, _ := New(Options{
		IPNet: ipnet,
		Size:  10,
	})
	newPool.CloneFrom(pool)

	// a fresh allocation must not overwrite the retained mappings
	baz := newPool.Lookup("baz.com")
	assert.NotEqual(t, foo, baz)
	assert.NotEqual(t, bar, baz)
	assert.Equal(t, foo, newPool.Lookup("foo.com"))
	assert.Equal(t, bar, newPool.Lookup("bar.com"))
	host, ok := newPool.LookBack(foo)
	assert.True(t, ok)
	assert.Equal(t, "foo.com", host)
}

func TestPool_Error(t *testing.T) {
	ipnet := netip.MustParsePrefix("192.168.0.1/31")
	_, err := New(Options{
		IPNet: ipnet,
		Size:  10,
	})

	assert.Error(t, err)
}

func TestPool_FlushFileCache(t *testing.T) {
	ipnet := netip.MustParsePrefix("192.168.0.1/28")
	pools := createPools(t, Options{
		IPNet: ipnet,
		Size:  10,
	})

	for _, pool := range pools {
		foo := pool.Lookup("foo.com")
		bar := pool.Lookup("baz.com")
		bax := pool.Lookup("baz.com")
		fox := pool.Lookup("foo.com")

		err := pool.FlushFakeIP()
		assert.Nil(t, err)

		next := pool.Lookup("baz.com")
		baz := pool.Lookup("foo.com")
		nero := pool.Lookup("foo.com")

		assert.Equal(t, foo, fox)
		assert.Equal(t, foo, next)
		assert.NotEqual(t, foo, baz)
		assert.Equal(t, bar, bax)
		assert.Equal(t, bar, baz)
		assert.NotEqual(t, bar, next)
		assert.Equal(t, baz, nero)
	}
}

func TestPool_FlushMemoryCache(t *testing.T) {
	ipnet := netip.MustParsePrefix("192.168.0.1/28")
	pool, _ := New(Options{
		IPNet: ipnet,
		Size:  10,
	})

	foo := pool.Lookup("foo.com")
	bar := pool.Lookup("baz.com")
	bax := pool.Lookup("baz.com")
	fox := pool.Lookup("foo.com")

	err := pool.FlushFakeIP()
	assert.Nil(t, err)

	next := pool.Lookup("baz.com")
	baz := pool.Lookup("foo.com")
	nero := pool.Lookup("foo.com")

	assert.Equal(t, foo, fox)
	assert.Equal(t, foo, next)
	assert.NotEqual(t, foo, baz)
	assert.Equal(t, bar, bax)
	assert.Equal(t, bar, baz)
	assert.NotEqual(t, bar, next)
	assert.Equal(t, baz, nero)
}

func TestPool_ReverseLookupAndCloneBudgets(t *testing.T) {
	options := Options{IPNet: netip.MustParsePrefix("198.18.0.0/24"), Size: 3}
	source, err := New(options)
	require.NoError(t, err)
	foo, bar, baz := source.Lookup("foo.test"), source.Lookup("bar.test"), source.Lookup("baz.test")
	_, _ = source.LookBack(foo)
	options.Size = 2
	clone, err := New(options)
	require.NoError(t, err)
	clone.Lookup("discard.test")
	clone.CloneFrom(source)
	clone.CloneFrom(clone)
	require.False(t, clone.Exist(bar))
	for host, ip := range map[string]netip.Addr{"foo.test": foo, "baz.test": baz} {
		got, ok := clone.LookBack(ip)
		require.True(t, ok)
		require.Equal(t, host, got)
	}
	_, _ = clone.LookBack(foo)
	clone.Lookup("next.test")
	require.True(t, clone.Exist(foo))
	require.False(t, clone.Exist(baz))
	require.Equal(t, baz, source.Lookup("baz.test"))
	require.NoError(t, clone.FlushFakeIP())
	require.Equal(t, foo, source.Lookup("foo.test"))
	require.Equal(t, bar, source.Lookup("bar.test"))
}

func TestPool_UnboundedMemory(t *testing.T) {
	for _, size := range []int{0, -1} {
		pool, err := New(Options{IPNet: netip.MustParsePrefix("198.18.0.0/16"), Size: size})
		require.NoError(t, err)
		first := pool.Lookup("first.test")
		for i := 0; i < 1001; i++ {
			pool.Lookup(fmt.Sprintf("host-%d.test", i))
		}
		require.Equal(t, first, pool.Lookup("first.test"))
	}
}

func TestPool_PersistentTransactionsAndRestore(t *testing.T) {
	for _, prefix := range []string{"198.18.0.0/29", "fc00::/125"} {
		t.Run(prefix, func(t *testing.T) {
			options := Options{IPNet: netip.MustParsePrefix(prefix)}
			path := filepath.Join(t.TempDir(), "cache.db")
			pool, db := createCachefileStore(t, options, path)
			txID := func() int {
				var id int
				require.NoError(t, db.View(func(tx *bbolt.Tx) error { id = tx.ID(); return nil }))
				return id
			}
			for _, host := range []string{"a.test", "b.test", "c.test", "d.test"} {
				before := txID()
				ip := pool.Lookup(host)
				require.Equal(t, before+1, txID(), "one commit per new mapping, including wraparound")
				require.Equal(t, ip, pool.Lookup(host))
				require.Equal(t, before+1, txID(), "cache hits must not commit")
			}
			pool.StoreState()
			require.NoError(t, db.Close())
			pool, db = createCachefileStore(t, options, path)
			require.True(t, pool.cycle)
			require.Equal(t, pool.first, pool.Lookup("d.test"))
			require.Equal(t, pool.first.Next(), pool.Lookup("e.test"))
			host, ok := pool.LookBack(pool.first)
			require.True(t, ok)
			require.Equal(t, "d.test", host)
			require.NoError(t, pool.FlushFakeIP())
			pool.StoreState()
			require.NoError(t, db.Close())
			pool, _ = createCachefileStore(t, options, path)
			require.False(t, pool.cycle)
			require.False(t, pool.Exist(pool.first))
			require.Equal(t, pool.first, pool.Lookup("fresh.test"))
		})
	}
}

func TestPool_ConcurrentFlushAndState(t *testing.T) {
	pools := createPools(t, Options{IPNet: netip.MustParsePrefix("198.18.0.0/28"), Size: 4})
	for i, pool := range pools {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			start := make(chan struct{})
			var workers sync.WaitGroup
			for worker := 0; worker < 4; worker++ {
				workers.Go(func() {
					<-start
					for j := 0; j < 32; j++ {
						switch worker {
						case 0:
							pool.Lookup(fmt.Sprintf("host-%d.test", j))
						case 1:
							_, _ = pool.LookBack(pool.first)
							pool.Exist(pool.first)
						case 2:
							if err := pool.FlushFakeIP(); err != nil {
								t.Error(err)
							}
						case 3:
							pool.StoreState()
						}
					}
				})
			}
			close(start)
			workers.Wait()
			require.NoError(t, pool.FlushFakeIP())
			require.Equal(t, pool.first, pool.Lookup("after.test"))
			host, ok := pool.LookBack(pool.first)
			require.True(t, ok)
			require.Equal(t, "after.test", host)
		})
	}
}
