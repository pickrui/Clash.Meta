package cachefile

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/metacubex/bbolt"
	"github.com/stretchr/testify/require"
)

func TestFakeIPMappingLegacyReplacementAndRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.db")
	require.NoError(t, os.WriteFile(path, legacyCacheBytes(t), 0600))
	cache := openTestCache(t, path, bbolt.Options{})
	for _, address := range []string{"198.18.0.4", "fc00::4"} {
		ip := netip.MustParseAddr(address)
		store := cache.FakeIpStore()
		if ip.Is6() {
			store = cache.FakeIpStore6()
		}
		require.NoError(t, store.PutMapping("second.test", ip.Next()))
		require.NoError(t, store.PutMapping("fixture.test", ip.Next()))
		_, exists := store.GetByHost("second.test")
		require.False(t, exists)
		_, exists = store.GetByIP(ip)
		require.False(t, exists)
		before := 0
		require.NoError(t, cache.DB.View(func(tx *bbolt.Tx) error { before = tx.ID(); return nil }))
		err := store.PutMapping(strings.Repeat("x", bbolt.MaxKeySize+1), ip.Next())
		require.ErrorIs(t, err, bbolt.ErrKeyTooLarge)
		require.NoError(t, cache.DB.View(func(tx *bbolt.Tx) error {
			if tx.ID() != before {
				return errors.New("failed mapping committed deletions")
			}
			bucket := tx.Bucket(store.bucketName)
			host := bucket.Get(ip.Next().AsSlice())
			gotIP, valid := netip.AddrFromSlice(bucket.Get(host))
			if string(host) != "fixture.test" || !valid || gotIP != ip.Next() {
				return errors.New("failed replacement changed either direction of the mapping")
			}
			return nil
		}))
	}
	require.NoError(t, cache.Close())
	cache = openTestCache(t, path, bbolt.Options{})
	for _, address := range []string{"198.18.0.5", "fc00::5"} {
		ip := netip.MustParseAddr(address)
		store := cache.FakeIpStore()
		if ip.Is6() {
			store = cache.FakeIpStore6()
		}
		got, exists := store.GetByHost("fixture.test")
		require.True(t, exists)
		require.Equal(t, ip, got)
		host, exists := store.GetByIP(ip)
		require.True(t, exists)
		require.Equal(t, "fixture.test", host)
	}
	require.Equal(t, "upload=1; download=2; total=3", cache.GetSubscriptionInfo("profile"))
}

func TestFakeIPMappingKeepsUnrelatedLegacyEntries(t *testing.T) {
	cache := openTestCache(t, filepath.Join(t.TempDir(), "cache.db"), bbolt.Options{})
	store := cache.FakeIpStore()
	first := netip.MustParseAddr("198.18.0.4")
	store.PutByIP(first, "stale.test")
	store.PutByHost("stale.test", first.Next())
	store.PutByIP(first.Next(), "stale.test")
	require.NoError(t, store.PutMapping("new.test", first))
	got, exists := store.GetByHost("stale.test")
	require.True(t, exists)
	require.Equal(t, first.Next(), got)

	store.PutByHost("other.test", first.Next())
	require.NoError(t, store.PutMapping("other.test", first.Next().Next()))
	host, exists := store.GetByIP(first.Next())
	require.True(t, exists)
	require.Equal(t, "stale.test", host)
}

func TestFakeIPMappingWithoutDatabase(t *testing.T) {
	cache := &CacheFile{}
	for _, store := range []*FakeIpStore{cache.FakeIpStore(), cache.FakeIpStore6()} {
		require.NoError(t, store.PutMapping("example.test", netip.MustParseAddr("198.18.0.4")))
		require.NoError(t, store.FlushFakeIP())
		_, exists := store.GetByHost("example.test")
		require.False(t, exists)
	}
}
