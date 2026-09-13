//go:build ignore

// Run against core c3cca07ec0430d8a05fba29f1381b0174f93f059 to regenerate
// the legacy cache fixture. The version guard prevents replacing it with a
// fixture written by the upgraded database implementation.
package main

import (
	"compress/gzip"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"

	"github.com/metacubex/bbolt"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/profile"
	"github.com/metacubex/mihomo/component/profile/cachefile"
)

func main() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		panic("missing build info")
	}
	legacy := false
	for _, module := range info.Deps {
		if module.Path == "github.com/metacubex/bbolt" && module.Version == "v0.0.0-20250725135710-010dbbbb7a5b" && module.Replace == nil {
			legacy = true
		}
	}
	if !legacy {
		panic("fixture must be generated with the pinned pre-upgrade bbolt")
	}
	if len(os.Args) != 2 {
		panic("usage: generate_legacy output.db.gz")
	}
	directory, err := os.MkdirTemp("", "flclash-legacy-cache-")
	must(err)
	defer os.RemoveAll(directory)
	path := filepath.Join(directory, "cache.db")
	db, err := bbolt.Open(path, 0600, &bbolt.Options{Timeout: time.Second, PageSize: 4096})
	must(err)
	cache := &cachefile.CacheFile{DB: db}
	profile.StoreSelected.Store(true)
	cache.SetSelected("Proxy / 香港", "legacy-node")
	for _, ipv6 := range []bool{false, true} {
		store, address := cache.FakeIpStore(), netip.MustParseAddr("198.18.0.4")
		if ipv6 {
			store, address = cache.FakeIpStore6(), netip.MustParseAddr("fc00::4")
		}
		store.PutByHost("fixture.test", address)
		store.PutByIP(address, "fixture.test")
	}
	cache.SetETagWithHash("https://fixture.test/profile", cachefile.EtagWithHash{
		Hash: utils.MakeHash([]byte("legacy-profile")), ETag: `"legacy-tag"`, Time: time.Unix(1700000000, 0).UTC(),
	})
	cache.SetSubscriptionInfo("profile", "upload=1; download=2; total=3")
	cache.SetStorage("script-cache", []byte{0, 1, 2, 0xff})
	must(cache.Close())
	source, err := os.Open(path)
	must(err)
	defer source.Close()
	target, err := os.Create(os.Args[1])
	must(err)
	compressed := gzip.NewWriter(target)
	_, err = io.Copy(compressed, source)
	must(err)
	must(compressed.Close())
	must(target.Close())
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
