package outbound

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/structure"
	"github.com/metacubex/mihomo/component/ech"
	"github.com/metacubex/mihomo/component/ech/echparser"
	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	obfs "github.com/metacubex/mihomo/transport/simple-obfs"
	shadowtls "github.com/metacubex/mihomo/transport/sing-shadowtls"
	"github.com/metacubex/mihomo/transport/snell"
	"github.com/metacubex/mihomo/transport/vmess"
	"github.com/metacubex/tls"
	utls "github.com/metacubex/utls"
)

type Snell struct {
	*Base
	option                *SnellOption
	psk                   []byte
	pool                  *snell.Pool
	obfsOption            *snellObfsOption
	echTLS                *vmess.TLSConfig
	shadowTLS             *shadowtls.ShadowTLSOption
	echTLSIdentityVersion int
	echTLSLegacyFallback  bool
	identity              bool
	version               int
	reuse                 bool
}

type SnellOption struct {
	BasicOption
	Name               string         `proxy:"name"`
	Server             string         `proxy:"server"`
	Port               int            `proxy:"port"`
	Psk                string         `proxy:"psk"`
	UDP                bool           `proxy:"udp,omitempty"`
	Version            int            `proxy:"version,omitempty"`
	Reuse              *bool          `proxy:"reuse,omitempty"`
	Identity           bool           `proxy:"identity,omitempty"`
	IdentityConfigured bool           `proxy:"-"`
	ObfsOpts           map[string]any `proxy:"obfs-opts,omitempty"`

	ShadowTLSPassword       string   `proxy:"shadow-tls-password,omitempty"`
	ShadowTLSSNI            string   `proxy:"shadow-tls-sni,omitempty"`
	ShadowTLSVersion        int      `proxy:"shadow-tls-version,omitempty"`
	ShadowTLSSkipCertVerify bool     `proxy:"shadow-tls-skip-cert-verify,omitempty"`
	ShadowTLSFingerprint    string   `proxy:"shadow-tls-fingerprint,omitempty"`
	ShadowTLSCertificate    string   `proxy:"shadow-tls-certificate,omitempty"`
	ShadowTLSPrivateKey     string   `proxy:"shadow-tls-private-key,omitempty"`
	ShadowTLSALPN           []string `proxy:"shadow-tls-alpn,omitempty"`
	ClientFingerprint       string   `proxy:"client-fingerprint,omitempty"`
}

func (s *Snell) Close() error {
	if s.pool != nil {
		return s.pool.Close()
	}
	return s.Base.Close()
}

type streamOption struct {
	psk             []byte
	version         int
	addr            string
	obfsOption      *snellObfsOption
	identity        bool
	identityVersion int
	legacyFallback  bool
}

type snellObfsOption struct {
	Mode              string            `obfs:"mode,omitempty"`
	ALPN              string            `obfs:"alpn,omitempty"`
	Protocol          string            `obfs:"protocol,omitempty"`
	IdentityVersion   int               `obfs:"identity-version,omitempty"`
	LegacyFallback    bool              `obfs:"legacy-fallback,omitempty"`
	Preconnect        int               `obfs:"preconnect,omitempty"`
	Host              string            `obfs:"host,omitempty"`
	SNI               string            `obfs:"sni,omitempty"`
	Path              string            `obfs:"path,omitempty"`
	TLS               bool              `obfs:"tls,omitempty"`
	ECHConfig         string            `obfs:"ech-config,omitempty"`
	ECHConfigFile     string            `obfs:"ech-config-file,omitempty"`
	CAFile            string            `obfs:"ca-file,omitempty"`
	Insecure          bool              `obfs:"insecure,omitempty"`
	Fingerprint       string            `obfs:"fingerprint,omitempty"`
	ClientFingerprint string            `obfs:"client-fingerprint,omitempty"`
	Certificate       string            `obfs:"certificate,omitempty"`
	PrivateKey        string            `obfs:"private-key,omitempty"`
	Headers           map[string]string `obfs:"headers,omitempty"`
	SkipCertVerify    bool              `obfs:"skip-cert-verify,omitempty"`
}

const defaultSnellClientFingerprint = "chrome"
const snellECHTLSSessionCacheCapacity = 32
const snellECHTLSPreconnectTimeout = 10 * time.Second
const (
	snellECHTLSALPN         = "snell-ech/1"
	snellECHTLSPreviousALPN = "oix-snell/1"
	snellECHTLSLegacyALPN   = "h2"
)

func resolveSnellECHTLSALPN(alpn, protocol string) (string, error) {
	if protocol == snellECHTLSPreviousALPN {
		protocol = snellECHTLSALPN
	}
	if alpn != "" && protocol != "" && alpn != protocol {
		return "", errors.New("ech-tls alpn and legacy protocol values conflict")
	}
	if alpn == "" {
		alpn = protocol
	}
	if alpn == "" {
		alpn = snellECHTLSALPN
	}
	if alpn != snellECHTLSALPN {
		return "", fmt.Errorf("unsupported ech-tls ALPN: %s", alpn)
	}
	return alpn, nil
}

func isSnellECHTLSMode(mode string) bool {
	return mode == "ech-tls"
}

func snellECHTLSHost(obfsOption *snellObfsOption, server string) string {
	if obfsOption.SNI != "" {
		return obfsOption.SNI
	}
	if obfsOption.Host != "" {
		return obfsOption.Host
	}
	return server
}

func resolveSnellClientFingerprint(obfsOption *snellObfsOption, option SnellOption) string {
	if obfsOption.ClientFingerprint != "" {
		return obfsOption.ClientFingerprint
	}
	if option.ClientFingerprint != "" {
		return option.ClientFingerprint
	}
	if globalFingerprint := tlsC.GetGlobalFingerprint(); globalFingerprint != "" {
		return globalFingerprint
	}
	return defaultSnellClientFingerprint
}

func snellECHTLSConfig(obfsOption *snellObfsOption) (*ech.Config, error) {
	if obfsOption.ECHConfig != "" && obfsOption.ECHConfigFile != "" {
		return nil, fmt.Errorf("ech-config and ech-config-file are mutually exclusive")
	}
	if obfsOption.ECHConfig == "" && obfsOption.ECHConfigFile == "" {
		return nil, fmt.Errorf("ech-tls requires ech-config or ech-config-file")
	}

	var list []byte
	var err error
	if obfsOption.ECHConfig != "" {
		list, err = base64.StdEncoding.DecodeString(strings.TrimSpace(obfsOption.ECHConfig))
		if err != nil {
			return nil, fmt.Errorf("base64 decode ech-config failed: %w", err)
		}
	} else {
		path := C.Path.Resolve(obfsOption.ECHConfigFile)
		if !C.Path.IsSafePath(path) {
			return nil, C.Path.ErrNotSafePath(path)
		}
		list, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read ech-config-file failed: %w", err)
		}
	}
	if configs, err := echparser.ParseECHConfigList(list); err != nil {
		return nil, fmt.Errorf("parse ech config list failed: %w", err)
	} else if len(configs) == 0 {
		return nil, fmt.Errorf("ech config list is empty")
	}

	return &ech.Config{
		GetEncryptedClientHelloConfigList: func(context.Context, string) ([]byte, error) {
			return list, nil
		},
	}, nil
}

func snellShadowTLSOption(option SnellOption) (*shadowtls.ShadowTLSOption, error) {
	if !hasSnellShadowTLSOption(option) {
		return nil, nil
	}
	if option.ShadowTLSPassword == "" {
		return nil, fmt.Errorf("shadow-tls password is empty")
	}
	if option.ShadowTLSSNI == "" {
		return nil, fmt.Errorf("shadow-tls sni is empty")
	}

	version := option.ShadowTLSVersion
	if version == 0 {
		version = 3
	}
	if version < 1 || version > 3 {
		return nil, fmt.Errorf("shadow-tls version error: %d", version)
	}
	alpn := option.ShadowTLSALPN
	if alpn == nil {
		alpn = shadowtls.DefaultALPN
	}
	return &shadowtls.ShadowTLSOption{
		Password:          option.ShadowTLSPassword,
		Host:              option.ShadowTLSSNI,
		Fingerprint:       option.ShadowTLSFingerprint,
		Certificate:       option.ShadowTLSCertificate,
		PrivateKey:        option.ShadowTLSPrivateKey,
		ClientFingerprint: resolveSnellClientFingerprint(&snellObfsOption{}, option),
		SkipCertVerify:    option.ShadowTLSSkipCertVerify,
		Version:           version,
		ALPN:              alpn,
	}, nil
}

func hasSnellShadowTLSOption(option SnellOption) bool {
	return option.ShadowTLSPassword != "" ||
		option.ShadowTLSSNI != "" ||
		option.ShadowTLSVersion != 0 ||
		option.ShadowTLSSkipCertVerify ||
		option.ShadowTLSFingerprint != "" ||
		option.ShadowTLSCertificate != "" ||
		option.ShadowTLSPrivateKey != "" ||
		option.ShadowTLSALPN != nil
}

func requiresSnellV4Identity(obfsMode string, shadowTLSOption *shadowtls.ShadowTLSOption) bool {
	return isSnellECHTLSMode(obfsMode) || shadowTLSOption != nil
}

func snellStreamConn(c net.Conn, option streamOption) (*snell.Snell, error) {
	switch option.obfsOption.Mode {
	case "tls":
		c = obfs.NewTLSObfs(c, option.obfsOption.Host)
	case "http":
		_, port, _ := net.SplitHostPort(option.addr)
		c = obfs.NewHTTPObfs(c, option.obfsOption.Host, port)
	}
	if option.identity && option.version == snell.Version4 {
		if isSnellECHTLSMode(option.obfsOption.Mode) {
			state := tlsC.GetTLSConnectionState(c)
			if !state.ECHAccepted {
				return nil, errors.New("snell ech-tls handshake did not accept ECH")
			}
			useExporterIdentity := state.NegotiatedProtocol == snellECHTLSALPN && option.identityVersion == 2
			if state.NegotiatedProtocol == snellECHTLSLegacyALPN && !option.legacyFallback {
				return nil, errors.New("snell ech-tls legacy ALPN was not enabled")
			}
			if state.NegotiatedProtocol != snellECHTLSALPN && state.NegotiatedProtocol != snellECHTLSLegacyALPN {
				return nil, fmt.Errorf("snell ech-tls negotiated ALPN %q", state.NegotiatedProtocol)
			}
			if useExporterIdentity {
				exporter, err := state.ExportKeyingMaterial(
					snell.IdentityExporterLabel,
					[]byte{},
					snell.IdentityExporterLength,
				)
				if err != nil {
					return nil, fmt.Errorf("snell ech-tls exporter: %w", err)
				}
				return snell.StreamConnWithExporterIdentity(c, option.psk, option.version, exporter), nil
			}
			return snell.StreamConnWithIdentity(c, option.psk, option.version), nil
		}
		return snell.StreamConnWithIdentity(c, option.psk, option.version), nil
	}
	return snell.StreamConn(c, option.psk, option.version), nil
}

// StreamConnContext implements C.ProxyAdapter
func (s *Snell) StreamConnContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	c, err := snellStreamConn(c, streamOption{
		psk:             s.psk,
		version:         s.version,
		addr:            s.addr,
		obfsOption:      s.obfsOption,
		identity:        s.identity,
		identityVersion: s.echTLSIdentityVersion,
		legacyFallback:  s.echTLSLegacyFallback,
	})
	if err != nil {
		return nil, err
	}
	err = s.writeHeaderContext(ctx, c, metadata)
	return c, err
}

func (s *Snell) writeHeaderContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (err error) {
	if ctx.Done() != nil {
		done := N.SetupContextForConn(ctx, c)
		defer done(&err)
	}

	if metadata.NetWork == C.UDP {
		err = snell.WriteUDPHeader(c, s.version)
		if err == nil && s.version >= snell.Version4 {
			if sc, ok := c.(*snell.Snell); ok {
				err = sc.ReadReply()
			}
		}
		return
	}
	err = snell.WriteHeaderWithReuse(c, metadata.String(), uint(metadata.DstPort), s.version, s.reuse)
	return
}

// DialContext implements C.ProxyAdapter
func (s *Snell) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	if s.pool != nil {
		for attempts := 0; attempts < 2; attempts++ {
			c, getErr := s.pool.GetContext(ctx)
			if getErr != nil {
				return nil, getErr
			}
			if err = s.writeHeaderContext(ctx, c, metadata); err != nil {
				_ = c.Close()
				continue
			}
			if poolConn, ok := c.(*snell.PoolConn); ok {
				poolConn.MarkReusable()
			}
			return NewConn(c, s), nil
		}
	}

	c, err := s.dialSnellTransport(ctx)
	if err != nil {
		return nil, err
	}

	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = s.StreamConnContext(ctx, c, metadata)
	return NewConn(c, s), err
}

// ListenPacketContext implements C.ProxyAdapter
func (s *Snell) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = s.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	c, err := s.dialSnellTransport(ctx)
	if err != nil {
		return nil, err
	}

	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = s.StreamConnContext(ctx, c, metadata)
	if err != nil {
		_ = c.Close()
		return nil, err
	}

	pc := snell.PacketConn(c)
	return newPacketConn(pc, s), nil
}

func (s *Snell) dialSnellTransport(ctx context.Context) (net.Conn, error) {
	c, err := s.dialer.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", s.addr, err)
	}
	if s.echTLS != nil {
		tlsConn, err := vmess.StreamTLSConn(ctx, c, s.echTLS)
		if err != nil {
			_ = c.Close()
			return nil, err
		}
		c = tlsConn
	}
	if s.shadowTLS != nil {
		shadowConn, err := shadowtls.NewShadowTLS(ctx, c, s.shadowTLS)
		if err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("%s shadow-tls connect error: %w", s.addr, err)
		}
		c = shadowConn
	}
	return c, nil
}

// SupportUOT implements C.ProxyAdapter
func (s *Snell) SupportUOT() bool {
	return true
}

// ProxyInfo implements C.ProxyAdapter
func (s *Snell) ProxyInfo() C.ProxyInfo {
	info := s.Base.ProxyInfo()
	info.DialerProxy = s.option.DialerProxy
	return info
}

func defaultSnellReuse(version int, option *bool) bool {
	if version == snell.Version4 {
		return option == nil || *option
	}
	return version == snell.Version2
}

func NewSnell(option SnellOption) (*Snell, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	psk := []byte(option.Psk)

	decoder := structure.NewDecoder(structure.Option{TagName: "obfs", WeaklyTypedInput: true})
	obfsOption := &snellObfsOption{}
	if err := decoder.Decode(option.ObfsOpts, obfsOption); err != nil {
		return nil, fmt.Errorf("snell %s initialize obfs error: %w", addr, err)
	}

	shadowTLSOption, err := snellShadowTLSOption(option)
	if err != nil {
		return nil, fmt.Errorf("snell %s initialize shadow-tls error: %w", addr, err)
	}
	switch obfsOption.Mode {
	case "tls", "http", "ech-tls", "":
	default:
		return nil, fmt.Errorf("snell %s obfs mode error: %s", addr, obfsOption.Mode)
	}
	if shadowTLSOption != nil && obfsOption.Mode != "" {
		return nil, fmt.Errorf("snell %s shadow-tls and obfs mode %s are mutually exclusive", addr, obfsOption.Mode)
	}
	if obfsOption.Host == "" && (obfsOption.Mode == "tls" || obfsOption.Mode == "http") {
		obfsOption.Host = "bing.com"
	}
	if isSnellECHTLSMode(obfsOption.Mode) {
		alpn, err := resolveSnellECHTLSALPN(obfsOption.ALPN, obfsOption.Protocol)
		if err != nil {
			return nil, fmt.Errorf("snell %s %w", addr, err)
		}
		obfsOption.ALPN = alpn
		if obfsOption.IdentityVersion == 0 {
			obfsOption.IdentityVersion = 2
		}
		if obfsOption.IdentityVersion != 1 && obfsOption.IdentityVersion != 2 {
			return nil, fmt.Errorf("snell %s unsupported identity version: %d", addr, obfsOption.IdentityVersion)
		}
		if obfsOption.Preconnect < 0 || obfsOption.Preconnect > 4 {
			return nil, fmt.Errorf("snell %s preconnect must be between 0 and 4", addr)
		}
		obfsOption.Host = snellECHTLSHost(obfsOption, option.Server)
		obfsOption.SkipCertVerify = obfsOption.SkipCertVerify || obfsOption.Insecure
		if obfsOption.SkipCertVerify {
			return nil, fmt.Errorf("snell %s %s requires certificate verification", addr, snellECHTLSALPN)
		}
	}
	if isSnellECHTLSMode(obfsOption.Mode) && obfsOption.CAFile != "" && obfsOption.SkipCertVerify {
		return nil, fmt.Errorf("snell %s ca-file and insecure/skip-cert-verify are mutually exclusive", addr)
	}

	// backward compatible
	if option.Version == 0 {
		if requiresSnellV4Identity(obfsOption.Mode, shadowTLSOption) {
			option.Version = snell.Version4
		} else {
			option.Version = snell.DefaultSnellVersion
		}
	}
	if option.Version == snell.Version5 {
		// Snell v5 servers are backward-compatible with v4 clients.
		option.Version = snell.Version4
	}
	identity := option.Identity
	if requiresSnellV4Identity(obfsOption.Mode, shadowTLSOption) && option.Version == snell.Version4 {
		if option.IdentityConfigured && !option.Identity {
			return nil, fmt.Errorf("snell %s identity cannot be disabled with ech-tls or shadow-tls", addr)
		}
		identity = true
	}
	switch option.Version {
	case snell.Version1, snell.Version2:
		if option.UDP {
			return nil, fmt.Errorf("snell version %d not support UDP", option.Version)
		}
	case snell.Version3, snell.Version4:
	default:
		return nil, fmt.Errorf("snell version error: %d", option.Version)
	}
	reuse := defaultSnellReuse(option.Version, option.Reuse)

	s := &Snell{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Snell,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option:                &option,
		psk:                   psk,
		obfsOption:            obfsOption,
		identity:              identity,
		version:               option.Version,
		reuse:                 reuse,
		shadowTLS:             shadowTLSOption,
		echTLSIdentityVersion: obfsOption.IdentityVersion,
		echTLSLegacyFallback:  obfsOption.LegacyFallback,
	}
	s.dialer = option.NewDialer(s.DialOptions())
	if isSnellECHTLSMode(obfsOption.Mode) {
		echConfig, err := snellECHTLSConfig(obfsOption)
		if err != nil {
			return nil, err
		}
		nextProtos := []string{obfsOption.ALPN}
		if obfsOption.LegacyFallback {
			nextProtos = append(nextProtos, snellECHTLSLegacyALPN)
		}
		s.echTLS = &vmess.TLSConfig{
			Host:                 obfsOption.Host,
			SkipCertVerify:       obfsOption.SkipCertVerify,
			CAFile:               obfsOption.CAFile,
			ClientFingerprint:    resolveSnellClientFingerprint(obfsOption, option),
			FingerPrint:          obfsOption.Fingerprint,
			Certificate:          obfsOption.Certificate,
			PrivateKey:           obfsOption.PrivateKey,
			NextProtos:           nextProtos,
			ECH:                  echConfig,
			ClientSessionCache:   tls.NewLRUClientSessionCache(snellECHTLSSessionCacheCapacity),
			UClientSessionCache:  utls.NewLRUClientSessionCache(snellECHTLSSessionCacheCapacity),
			DisableRenegotiation: true,
		}
	}

	if s.reuse {
		s.pool = snell.NewPool(func(ctx context.Context) (*snell.Snell, error) {
			c, err := s.dialSnellTransport(ctx)
			if err != nil {
				return nil, err
			}

			stream, err := snellStreamConn(c, streamOption{
				psk:             psk,
				version:         option.Version,
				addr:            addr,
				obfsOption:      obfsOption,
				identity:        identity,
				identityVersion: obfsOption.IdentityVersion,
				legacyFallback:  obfsOption.LegacyFallback,
			})
			if err != nil {
				_ = c.Close()
				return nil, err
			}
			if s.version == snell.Version4 {
				if err = stream.Warmup(); err != nil {
					_ = stream.Close()
					return nil, err
				}
			}
			return stream, nil
		})
		if obfsOption.Preconnect > 0 {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), snellECHTLSPreconnectTimeout)
				defer cancel()
				s.pool.Warm(ctx, obfsOption.Preconnect)
			}()
		}
	}
	return s, nil
}
