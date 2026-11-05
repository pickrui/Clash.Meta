package fakeip

import (
	"net/netip"

	"github.com/metacubex/mihomo/component/profile/cachefile"
	"github.com/metacubex/mihomo/log"
)

type cachefileStore struct {
	cache *cachefile.FakeIpStore
}

// GetByHost implements store.GetByHost
func (c *cachefileStore) GetByHost(host string) (netip.Addr, bool) {
	return c.cache.GetByHost(host)
}

// GetByIP implements store.GetByIP
func (c *cachefileStore) GetByIP(ip netip.Addr) (string, bool) {
	return c.cache.GetByIP(ip)
}

func (c *cachefileStore) PutMapping(host string, ip netip.Addr) {
	if err := c.cache.PutMapping(host, ip); err != nil {
		log.Warnln("[CacheFile] write cache to %s failed: %s", c.cache.DB.Path(), err.Error())
	}
}

// Exist implements store.Exist
func (c *cachefileStore) Exist(ip netip.Addr) bool {
	_, exist := c.GetByIP(ip)
	return exist
}

// CloneTo implements store.CloneTo
// already persistence
func (c *cachefileStore) CloneTo(store store) {}

// FlushFakeIP implements store.FlushFakeIP
func (c *cachefileStore) FlushFakeIP() error {
	return c.cache.FlushFakeIP()
}

func newCachefileStore(cache *cachefile.CacheFile, prefix netip.Prefix) *cachefileStore {
	if prefix.Addr().Is6() {
		return &cachefileStore{cache.FakeIpStore6()}
	} else {
		return &cachefileStore{cache.FakeIpStore()}
	}
}
