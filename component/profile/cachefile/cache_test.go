package cachefile

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/bbolt"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/profile"
	C "github.com/metacubex/mihomo/constant"
)

func openTestCache(t *testing.T, path string, options bbolt.Options) *CacheFile {
	t.Helper()
	options.Timeout = 100 * time.Millisecond
	options.NoStatistics = true
	db, err := bbolt.Open(path, 0600, &options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &CacheFile{DB: db}
}

func enableSelectedCache(t *testing.T) {
	t.Helper()
	previous := profile.StoreSelected.Load()
	profile.StoreSelected.Store(true)
	t.Cleanup(func() { profile.StoreSelected.Store(previous) })
}

func legacyCacheBytes(t *testing.T) []byte {
	t.Helper()
	file, err := os.Open("testdata/bbolt-1.4-cache.db.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	compressed, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer compressed.Close()
	data, err := io.ReadAll(compressed)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func assertLegacyCache(t *testing.T, cache *CacheFile) {
	t.Helper()
	if cache.SelectedMap()["Proxy / 香港"] != "legacy-node" {
		t.Fatal("legacy selection lost")
	}
	for _, ipv6 := range []bool{false, true} {
		store, want := cache.FakeIpStore(), netip.MustParseAddr("198.18.0.4")
		if ipv6 {
			store, want = cache.FakeIpStore6(), netip.MustParseAddr("fc00::4")
		}
		if got, ok := store.GetByHost("fixture.test"); !ok || got != want {
			t.Fatalf("legacy host mapping: %v %v", got, ok)
		}
		if got, ok := store.GetByIP(want); !ok || got != "fixture.test" {
			t.Fatalf("legacy IP mapping: %s %v", got, ok)
		}
	}
	etag := cache.GetETagWithHash("https://fixture.test/profile")
	if etag.ETag != `"legacy-tag"` || !etag.Hash.Equal(utils.MakeHash([]byte("legacy-profile"))) || !etag.Time.Equal(time.Unix(1700000000, 0)) {
		t.Fatalf("legacy ETag changed: %+v", etag)
	}
	if cache.GetSubscriptionInfo("profile") != "upload=1; download=2; total=3" {
		t.Fatal("legacy subscription info lost")
	}
	if !bytes.Equal(cache.GetStorage("script-cache"), []byte{0, 1, 2, 0xff}) {
		t.Fatal("legacy script storage lost")
	}
}

func TestCacheFileLegacyRoundTrip(t *testing.T) {
	enableSelectedCache(t)
	path := filepath.Join(t.TempDir(), "cache.db")
	if err := os.WriteFile(path, legacyCacheBytes(t), 0600); err != nil {
		t.Fatal(err)
	}
	cache := openTestCache(t, path, bbolt.Options{})
	assertLegacyCache(t, cache)
	cache.SetSelected("Proxy / 香港", "updated-node")
	cache.SetSubscriptionInfo("profile", "updated-subscription")
	cache.SetStorage("script-cache", []byte("updated-storage"))
	cache.SetETagWithHash("https://fixture.test/profile", EtagWithHash{ETag: "updated-tag"})
	if err := cache.Close(); err != nil {
		t.Fatal(err)
	}
	cache = openTestCache(t, path, bbolt.Options{})
	if cache.SelectedMap()["Proxy / 香港"] != "updated-node" || cache.GetSubscriptionInfo("profile") != "updated-subscription" || string(cache.GetStorage("script-cache")) != "updated-storage" || cache.GetETagWithHash("https://fixture.test/profile").ETag != "updated-tag" {
		t.Fatal("updates did not survive reopen")
	}
	cache.FakeIpStore().DelByIP(netip.MustParseAddr("198.18.0.4"))
	if _, ok := cache.FakeIpStore().GetByHost("fixture.test"); ok {
		t.Fatal("reverse deletion left host mapping")
	}
	if _, ok := cache.FakeIpStore().GetByIP(netip.MustParseAddr("198.18.0.4")); ok {
		t.Fatal("reverse deletion left IP mapping")
	}
	if _, ok := cache.FakeIpStore6().GetByHost("fixture.test"); !ok {
		t.Fatal("IPv4 deletion affected IPv6")
	}
	if err := cache.FakeIpStore6().FlushFakeIP(); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.FakeIpStore6().GetByHost("fixture.test"); ok {
		t.Fatal("IPv6 flush left mapping")
	}
	cache.DeleteStorage("script-cache")
	if cache.GetStorage("script-cache") != nil || cache.GetSubscriptionInfo("profile") != "updated-subscription" {
		t.Fatal("storage deletion crossed buckets")
	}
	if !reflect.DeepEqual(cache.DB.Stats(), bbolt.Stats{}) {
		t.Fatal("NoStatistics did not disable counters")
	}
}

func TestCacheFileBatchRollbackAndConcurrentWrites(t *testing.T) {
	cache := openTestCache(t, filepath.Join(t.TempDir(), "cache.db"), bbolt.Options{})
	cache.SetSubscriptionInfo("stable", "before")
	rollback := errors.New("rollback test transaction")
	if err := cache.DB.Update(func(tx *bbolt.Tx) error {
		if err := tx.Bucket(bucketSubscriptionInfo).Put([]byte("stable"), []byte("after")); err != nil {
			return err
		}
		return rollback
	}); !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	if cache.GetSubscriptionInfo("stable") != "before" {
		t.Fatal("rolled back data became visible")
	}
	var writers sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		writers.Add(1)
		go func(worker int) {
			defer writers.Done()
			key := fmt.Sprintf("worker-%d", worker)
			for i := 0; i < 8; i++ {
				value := fmt.Sprint(i)
				cache.SetSubscriptionInfo(key, value)
				if cache.GetSubscriptionInfo(key) != value {
					t.Errorf("concurrent write lost for %s", key)
					return
				}
			}
		}(worker)
	}
	writers.Wait()
	if err := cache.DB.View(func(tx *bbolt.Tx) error {
		var checkErr error
		for err := range tx.Check() {
			checkErr = errors.Join(checkErr, err)
		}
		return checkErr
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCacheFileStorageEvictionAndCorruption(t *testing.T) {
	cache := openTestCache(t, filepath.Join(t.TempDir(), "cache.db"), bbolt.Options{})
	cache.SetSubscriptionInfo("keep", "subscription")
	cache.SetStorage("older", bytes.Repeat([]byte("a"), 600*1024))
	cache.SetStorage("newer", bytes.Repeat([]byte("b"), 600*1024))
	if cache.GetStorage("older") != nil || len(cache.GetStorage("newer")) != 600*1024 {
		t.Fatal("storage size eviction changed")
	}
	if err := cache.DB.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketStorage).Put([]byte("corrupt"), []byte{0xc1})
	}); err != nil {
		t.Fatal(err)
	}
	if cache.GetStorage("corrupt") != nil {
		t.Fatal("corrupt storage was decoded")
	}
	if err := cache.DB.View(func(tx *bbolt.Tx) error {
		if tx.Bucket(bucketStorage).Get([]byte("corrupt")) != nil {
			return errors.New("corrupt entry was not removed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if cache.GetSubscriptionInfo("keep") != "subscription" {
		t.Fatal("storage eviction affected another bucket")
	}
}

func TestInitCacheRecoversOnlyInvalidFiles(t *testing.T) {
	enableSelectedCache(t)
	previousHome, previousCache := C.Path.HomeDir(), defaultCache
	t.Cleanup(func() { C.SetHomeDir(previousHome); defaultCache = previousCache })
	for _, kind := range []string{"new", "legacy", "corrupt", "locked"} {
		t.Run(kind, func(t *testing.T) {
			C.SetHomeDir(t.TempDir())
			path := C.Path.Cache()
			var locked *CacheFile
			switch kind {
			case "legacy", "locked":
				if err := os.WriteFile(path, legacyCacheBytes(t), 0600); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(path, make([]byte, 2*os.Getpagesize()), 0600); err != nil {
					t.Fatal(err)
				}
			}
			var before []byte
			if kind == "locked" {
				locked = openTestCache(t, path, bbolt.Options{})
				var err error
				before, err = os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
			}
			initCache()
			if kind == "locked" {
				if defaultCache.DB != nil {
					_ = defaultCache.Close()
					t.Fatal("locked database opened twice")
				}
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("lock failure modified existing cache")
				}
				if err := locked.Close(); err != nil {
					t.Fatal(err)
				}
				return
			}
			if defaultCache.DB == nil {
				t.Fatal("cache failed to open")
			}
			cache := defaultCache
			t.Cleanup(func() { _ = cache.Close() })
			if kind == "legacy" {
				assertLegacyCache(t, cache)
			}
			cache.SetSelected("test-group", "test-node")
			if cache.SelectedMap()["test-group"] != "test-node" {
				t.Fatal("initialized cache not writable")
			}
			if !reflect.DeepEqual(cache.DB.Stats(), bbolt.Stats{}) {
				t.Fatal("production cache statistics still enabled")
			}
		})
	}
}
