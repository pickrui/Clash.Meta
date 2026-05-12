package outbound

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/structure"
	"github.com/metacubex/mihomo/component/proxydialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/anytls"
	obfs "github.com/metacubex/mihomo/transport/simple-obfs"
	"github.com/metacubex/mihomo/transport/snell"
	"github.com/metacubex/mihomo/transport/vmess"

	M "github.com/metacubex/sing/common/metadata"
)

type Snell struct {
	*Base
	option     *SnellOption
	psk        []byte
	pool       *snell.Pool
	obfsOption *simpleObfsOption
	anyTLS     *anytls.Client
	identity   bool
	reuse      bool
	version    int
}

type SnellOption struct {
	BasicOption
	Name     string         `proxy:"name"`
	Server   string         `proxy:"server"`
	Port     int            `proxy:"port"`
	Psk      string         `proxy:"psk"`
	UDP      bool           `proxy:"udp,omitempty"`
	Version  int            `proxy:"version,omitempty"`
	Reuse    *bool          `proxy:"reuse,omitempty"`
	Identity bool           `proxy:"identity,omitempty"`
	ObfsOpts map[string]any `proxy:"obfs-opts,omitempty"`
}

type streamOption struct {
	psk        []byte
	version    int
	addr       string
	obfsOption *simpleObfsOption
	identity   bool
}

func snellStreamConn(c net.Conn, option streamOption) *snell.Snell {
	switch option.obfsOption.Mode {
	case "tls":
		c = obfs.NewTLSObfs(c, option.obfsOption.Host)
	case "http":
		_, port, _ := net.SplitHostPort(option.addr)
		c = obfs.NewHTTPObfs(c, option.obfsOption.Host, port)
	}
	if option.identity && option.version == snell.Version4 {
		return snell.StreamConnWithIdentity(c, option.psk, option.version)
	}
	return snell.StreamConn(c, option.psk, option.version)
}

// StreamConnContext implements C.ProxyAdapter
func (s *Snell) StreamConnContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	c = snellStreamConn(c, streamOption{psk: s.psk, version: s.version, addr: s.addr, obfsOption: s.obfsOption, identity: s.identity})
	err := s.writeHeaderContext(ctx, c, metadata)
	return c, err
}

func (s *Snell) writeHeaderContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (err error) {
	if ctx.Done() != nil {
		done := N.SetupContextForConn(ctx, c)
		defer done(&err)
	}

	if metadata.NetWork == C.UDP {
		if err = snell.WriteUDPHeader(c, s.version); err != nil {
			return err
		}
		if s.version == snell.Version4 {
			return snell.ReadTunnelReply(c)
		}
		return nil
	}
	err = snell.WriteHeader(c, metadata.String(), uint(metadata.DstPort), s.version, s.reuse)
	return
}

// DialContext implements C.ProxyAdapter
func (s *Snell) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	if s.pool != nil {
		c, err := s.pool.Get()
		if err != nil {
			return nil, err
		}

		if err = s.writeHeaderContext(ctx, c, metadata); err != nil {
			_ = c.Close()
			return nil, err
		}
		return NewConn(c, s), err
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

	pc := snell.PacketConn(c)
	return newPacketConn(pc, s), nil
}

func (s *Snell) dialSnellTransport(ctx context.Context) (net.Conn, error) {
	if s.anyTLS != nil {
		return s.anyTLS.CreateRawStream(ctx)
	}
	c, err := s.dialer.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", s.addr, err)
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
	obfsOption := &simpleObfsOption{}
	if err := decoder.Decode(option.ObfsOpts, obfsOption); err != nil {
		return nil, fmt.Errorf("snell %s initialize obfs error: %w", addr, err)
	}
	if obfsOption.Host == "" && (obfsOption.Mode == "tls" || obfsOption.Mode == "http") {
		obfsOption.Host = "bing.com"
	}

	switch obfsOption.Mode {
	case "tls", "http", "anytls", "":
	default:
		return nil, fmt.Errorf("snell %s obfs mode error: %s", addr, obfsOption.Mode)
	}
	if obfsOption.Mode == "anytls" && obfsOption.Password == "" {
		return nil, fmt.Errorf("snell %s anytls password is empty", addr)
	}

	// backward compatible
	if option.Version == 0 {
		option.Version = snell.DefaultSnellVersion
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
		option:     &option,
		psk:        psk,
		obfsOption: obfsOption,
		identity:   option.Identity,
		reuse:      reuse,
		version:    option.Version,
	}
	s.dialer = option.NewDialer(s.DialOptions())
	if obfsOption.Mode == "anytls" {
		singDialer := proxydialer.NewSingDialer(s.dialer)
		tlsConfig := &vmess.TLSConfig{
			Host:           obfsOption.Host,
			SkipCertVerify: obfsOption.SkipCertVerify,
		}
		if tlsConfig.Host == "" {
			tlsConfig.Host = option.Server
		}
		s.anyTLS = anytls.NewClient(context.TODO(), anytls.ClientConfig{
			Password:                 obfsOption.Password,
			Server:                   M.ParseSocksaddrHostPort(option.Server, uint16(option.Port)),
			Dialer:                   singDialer,
			TLSConfig:                tlsConfig,
			IdleSessionCheckInterval: 30 * time.Second,
			IdleSessionTimeout:       30 * time.Second,
		})
	}

	if reuse {
		s.pool = snell.NewPool(func(ctx context.Context) (*snell.Snell, error) {
			c, err := s.dialSnellTransport(ctx)
			if err != nil {
				return nil, err
			}

			return snellStreamConn(c, streamOption{psk: psk, version: option.Version, addr: addr, obfsOption: obfsOption, identity: option.Identity}), nil
		})
	}
	return s, nil
}

func (s *Snell) Close() error {
	if s.anyTLS != nil {
		return s.anyTLS.Close()
	}
	return s.Base.Close()
}
