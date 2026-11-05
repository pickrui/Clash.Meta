package cachefile

import (
	"bytes"
	"net/netip"

	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/bbolt"
)

type FakeIpStore struct {
	*CacheFile
	bucketName []byte
}

func (c *CacheFile) FakeIpStore() *FakeIpStore {
	return &FakeIpStore{c, bucketFakeip}
}

func (c *CacheFile) FakeIpStore6() *FakeIpStore {
	return &FakeIpStore{c, bucketFakeip6}
}

func (c *FakeIpStore) GetByHost(host string) (ip netip.Addr, exist bool) {
	if c.DB == nil {
		return
	}
	c.DB.View(func(t *bbolt.Tx) error {
		if bucket := t.Bucket(c.bucketName); bucket != nil {
			if v := bucket.Get([]byte(host)); v != nil {
				ip, exist = netip.AddrFromSlice(v)
			}
		}
		return nil
	})
	return
}

func (c *FakeIpStore) PutByHost(host string, ip netip.Addr) {
	if c.DB == nil {
		return
	}
	err := c.DB.Batch(func(t *bbolt.Tx) error {
		bucket, err := t.CreateBucketIfNotExists(c.bucketName)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(host), ip.AsSlice())
	})
	if err != nil {
		log.Warnln("[CacheFile] write cache to %s failed: %s", c.DB.Path(), err.Error())
	}
}

func (c *FakeIpStore) GetByIP(ip netip.Addr) (host string, exist bool) {
	if c.DB == nil {
		return
	}
	c.DB.View(func(t *bbolt.Tx) error {
		if bucket := t.Bucket(c.bucketName); bucket != nil {
			if v := bucket.Get(ip.AsSlice()); v != nil {
				host, exist = string(v), true
			}
		}
		return nil
	})
	return
}

func (c *FakeIpStore) PutByIP(ip netip.Addr, host string) {
	if c.DB == nil {
		return
	}
	err := c.DB.Batch(func(t *bbolt.Tx) error {
		bucket, err := t.CreateBucketIfNotExists(c.bucketName)
		if err != nil {
			return err
		}
		return bucket.Put(ip.AsSlice(), []byte(host))
	})
	if err != nil {
		log.Warnln("[CacheFile] write cache to %s failed: %s", c.DB.Path(), err.Error())
	}
}

func (c *FakeIpStore) PutMapping(host string, ip netip.Addr) error {
	if c.DB == nil {
		return nil
	}
	hostKey, addr := []byte(host), ip.AsSlice()
	return c.DB.Update(func(t *bbolt.Tx) error {
		bucket, err := t.CreateBucketIfNotExists(c.bucketName)
		if err != nil {
			return err
		}
		if oldHost := bucket.Get(addr); len(oldHost) > 0 && !bytes.Equal(oldHost, hostKey) && bytes.Equal(bucket.Get(oldHost), addr) {
			if err := bucket.Delete(oldHost); err != nil {
				return err
			}
		}
		if oldIP := bucket.Get(hostKey); len(oldIP) > 0 && !bytes.Equal(oldIP, addr) && bytes.Equal(bucket.Get(oldIP), hostKey) {
			if err := bucket.Delete(oldIP); err != nil {
				return err
			}
		}
		if err := bucket.Put(hostKey, addr); err != nil {
			return err
		}
		return bucket.Put(addr, hostKey)
	})
}

func (c *FakeIpStore) DelByIP(ip netip.Addr) {
	if c.DB == nil {
		return
	}

	addr := ip.AsSlice()
	err := c.DB.Batch(func(t *bbolt.Tx) error {
		bucket, err := t.CreateBucketIfNotExists(c.bucketName)
		if err != nil {
			return err
		}
		host := bucket.Get(addr)
		err = bucket.Delete(addr)
		if len(host) > 0 {
			if err = bucket.Delete(host); err != nil {
				return err
			}
		}
		return err
	})
	if err != nil {
		log.Warnln("[CacheFile] write cache to %s failed: %s", c.DB.Path(), err.Error())
	}
}

func (c *FakeIpStore) FlushFakeIP() error {
	if c.DB == nil {
		return nil
	}
	err := c.DB.Batch(func(t *bbolt.Tx) error {
		bucket := t.Bucket(c.bucketName)
		if bucket == nil {
			return nil
		}
		return t.DeleteBucket(c.bucketName)
	})
	return err
}
