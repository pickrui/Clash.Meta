package vmess

import (
	"crypto/x509"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/metacubex/mihomo/common/lru"
	"github.com/metacubex/tls"
)

const tlsSessionCacheBuckets = 128

type tlsSessionIdentity struct {
	remote, host, name, fingerprint, alpn string
	skipVerify                            bool
}

type tlsSessionCaches struct {
	mu    sync.Mutex
	roots *x509.CertPool
	cache *lru.LruCache[tlsSessionIdentity, tls.ClientSessionCache]
}

var sharedTLSSessions tlsSessionCaches

// Tickets stay with one endpoint: servers sharing an SNI would reject each other's tickets, and presenting the same
// ticket to several node addresses links them to one client.
func (c *tlsSessionCaches) forConfig(cfg *TLSConfig, config *tls.Config, remote net.Addr) tls.ClientSessionCache {
	if config.ClientSessionCache != nil {
		return config.ClientSessionCache
	}
	// File-backed identities can change without replacing the outbound.
	if cfg.CAFile != "" || cfg.Certificate != "" || cfg.PrivateKey != "" || cfg.ECH != nil {
		return nil
	}
	var alpn strings.Builder
	for _, protocol := range cfg.NextProtos {
		alpn.WriteString(strconv.Itoa(len(protocol)))
		alpn.WriteByte(':')
		alpn.WriteString(protocol)
	}
	key := tlsSessionIdentity{
		host: cfg.Host, name: cfg.NameCertVerify, fingerprint: cfg.FingerPrint,
		skipVerify: cfg.SkipCertVerify, alpn: alpn.String(),
	}
	if remote != nil {
		key.remote = remote.String()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache == nil || c.roots != config.RootCAs {
		c.roots = config.RootCAs
		c.cache = lru.New(lru.WithSize[tlsSessionIdentity, tls.ClientSessionCache](tlsSessionCacheBuckets))
	}
	cache, _ := c.cache.GetOrStore(key, func() tls.ClientSessionCache {
		return tls.NewLRUClientSessionCache(1)
	})
	return cache
}
