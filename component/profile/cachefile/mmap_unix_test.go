//go:build darwin || linux

package cachefile

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/metacubex/bbolt"
)

func TestCacheFileMmapFallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.db")
	// Invalid flags make mmap fail on these kernels, exercising Open's fallback
	// dispatch without changing the production options or using a special FS.
	cache := openTestCache(t, path, bbolt.Options{MmapFlags: -1})
	payload := bytes.Repeat([]byte("fallback"), 8192)
	// Grow beyond the initial mapping while all reads use the heap mirror.
	for i := 0; i < 12; i++ {
		cache.SetSubscriptionInfo(fmt.Sprint(i), string(payload))
	}
	for i := 0; i < 12; i++ {
		if cache.GetSubscriptionInfo(fmt.Sprint(i)) != string(payload) {
			t.Fatalf("fallback write/read %d", i)
		}
	}
	if err := cache.Close(); err != nil {
		t.Fatal(err)
	}
	for _, flags := range []int{0, -1} {
		cache = openTestCache(t, path, bbolt.Options{MmapFlags: flags, ReadOnly: true})
		for i := 0; i < 12; i++ {
			if cache.GetSubscriptionInfo(fmt.Sprint(i)) != string(payload) {
				t.Fatalf("reopen flags=%d key=%d", flags, i)
			}
		}
		if err := cache.DB.Update(func(*bbolt.Tx) error { return nil }); !errors.Is(err, bbolt.ErrDatabaseReadOnly) {
			t.Fatalf("read-only update: %v", err)
		}
		if err := cache.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
