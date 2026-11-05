package anytls

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"

	"github.com/metacubex/mihomo/adapter/inbound"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/jls"
	"github.com/metacubex/mihomo/listener/restls"
	"github.com/metacubex/mihomo/listener/shadowtls"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/ntp"
	"github.com/metacubex/mihomo/transport/anytls/padding"
	"github.com/metacubex/mihomo/transport/anytls/session"

	"github.com/metacubex/sing/common/auth"

	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/tls"
)

type Listener struct {
	closed    atomic.Bool
	config    LC.AnyTLSServer
	listeners []net.Listener
	tlsConfig *tls.Config
	userMap   map[[32]byte]string
	padding   atomic.Pointer[padding.PaddingFactory]
}

func New(config LC.AnyTLSServer, lc C.InboundListenConfig, tunnel C.Tunnel, additions ...inbound.Addition) (_ *Listener, err error) {
	if config.ResTLS.Enable {
		if config.Certificate != "" || config.PrivateKey != "" {
			return nil, errors.New("certificate is unavailable in Restls")
		}
		if ca.ClientAuthTypeFromString(config.ClientAuthType) != tls.NoClientCert || config.ClientAuthCert != "" {
			return nil, errors.New("client-auth is unavailable in Restls")
		}
		if config.EchKey != "" {
			return nil, errors.New("ECH is unavailable in Restls")
		}
	}
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-ANYTLS"),
			inbound.WithSpecialRules(""),
		}
	}

	var shadowTLSBuilder *shadowtls.Builder
	var jlsBuilder *jls.Builder
	tlsConfig := &tls.Config{Time: ntp.Now}
	if config.Certificate != "" && config.PrivateKey != "" {
		certLoader, err := ca.NewTLSKeyPairLoader(config.Certificate, config.PrivateKey)
		if err != nil {
			return nil, err
		}
		tlsConfig.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return certLoader()
		}

		if config.EchKey != "" {
			err = ech.LoadECHKey(config.EchKey, tlsConfig)
			if err != nil {
				return nil, err
			}
		}
	}
	tlsConfig.ClientAuth = ca.ClientAuthTypeFromString(config.ClientAuthType)
	if len(config.ClientAuthCert) > 0 {
		if tlsConfig.ClientAuth == tls.NoClientCert {
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}
	if tlsConfig.ClientAuth == tls.VerifyClientCertIfGiven || tlsConfig.ClientAuth == tls.RequireAndVerifyClientCert {
		pool, err := ca.LoadCertificates(config.ClientAuthCert)
		if err != nil {
			return nil, err
		}
		tlsConfig.ClientCAs = pool
	}
	if tlsConfig.ClientAuth != tls.NoClientCert && tlsConfig.GetCertificate == nil {
		return nil, errors.New("client-auth requires certificate")
	}
	securityModes := make([]string, 0, 4)
	if tlsConfig.GetCertificate != nil {
		securityModes = append(securityModes, "certificate")
	}
	if config.ShadowTLS.Enable {
		securityModes = append(securityModes, "shadow-tls")
	}
	if config.ResTLS.Enable {
		securityModes = append(securityModes, "res-tls")
	}
	if config.JLSConfig.Enable {
		securityModes = append(securityModes, "jls")
	}
	if len(securityModes) > 1 {
		return nil, errors.New("security modes are mutually exclusive: " + strings.Join(securityModes, ", "))
	}
	if config.ShadowTLS.Enable {
		shadowTLSBuilder, err = shadowtls.New(config.ShadowTLS, tunnel)
		if err != nil {
			return nil, err
		}
	}
	if config.ResTLS.Enable {
		if err := restls.Validate(config.ResTLS); err != nil {
			return nil, err
		}
	}
	if config.JLSConfig.Enable {
		jlsBuilder, err = jls.New(config.JLSConfig, tunnel)
		if err != nil {
			return nil, err
		}
	}

	sl := &Listener{
		config:    config,
		tlsConfig: tlsConfig,
		userMap:   make(map[[32]byte]string),
	}
	defer func(owned *Listener) {
		if err != nil {
			_ = owned.Close()
		}
	}(sl)

	for user, password := range config.Users {
		sl.userMap[sha256.Sum256([]byte(password))] = user
	}

	if len(config.PaddingScheme) > 0 {
		if !padding.UpdatePaddingScheme([]byte(config.PaddingScheme), &sl.padding) {
			return nil, errors.New("incorrect padding scheme format")
		}
	} else {
		padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &sl.padding)
	}

	// Using sing handler can automatically handle UoT
	h, err := sing.NewListenerHandler(sing.ListenerConfig{
		Tunnel:    tunnel,
		Type:      C.ANYTLS,
		Additions: additions,
	})
	if err != nil {
		return nil, err
	}

	for _, addr := range strings.Split(config.Listen, ",") {
		addr := addr

		//TCP
		l, err := lc.Listen(context.Background(), "tcp", addr)
		if err != nil {
			return nil, err
		}
		if shadowTLSBuilder != nil {
			l = shadowTLSBuilder.NewListener(l)
		} else if config.ResTLS.Enable {
			wrapped, wrapErr := restls.NewListener(l, config.ResTLS, tunnel)
			if wrapErr != nil {
				_ = l.Close()
				return nil, wrapErr
			}
			l = wrapped
		} else if jlsBuilder != nil {
			l = jlsBuilder.NewListener(l)
		} else if tlsConfig.GetCertificate != nil {
			l = tls.NewListener(l, tlsConfig)
		} else if !config.AllowInsecure {
			_ = l.Close()
			return nil, errors.New("disallow using AnyTLS without certificates/shadow-tls/res-tls/jls/allow-insecure config")
		}
		sl.listeners = append(sl.listeners, l)

		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					if sl.closed.Load() {
						break
					}
					continue
				}
				go sl.HandleConn(c, h)
			}
		}()
	}

	return sl, nil
}

func (l *Listener) Close() error {
	if !l.closed.CompareAndSwap(false, true) {
		return nil
	}
	var retErr error
	for _, lis := range l.listeners {
		err := lis.Close()
		if err != nil {
			retErr = err
		}
	}
	return retErr
}

func (l *Listener) Config() string {
	return l.config.String()
}

func (l *Listener) AddrList() (addrList []net.Addr) {
	for _, lis := range l.listeners {
		addrList = append(addrList, lis.Addr())
	}
	return
}

func (l *Listener) HandleConn(conn net.Conn, h *sing.ListenerHandler) {
	ctx := context.TODO()
	defer conn.Close()

	// Authentication is a byte-stream header. Restls may split it across records;
	// read exactly the header and padding without consuming the first session frame.
	var passwordSha256 [32]byte
	if _, err := io.ReadFull(conn, passwordSha256[:]); err != nil {
		return
	}
	if user, ok := l.userMap[passwordSha256]; ok {
		ctx = auth.ContextWithUser(ctx, user)
	} else {
		return
	}
	var paddingBytes [2]byte
	if _, err := io.ReadFull(conn, paddingBytes[:]); err != nil {
		return
	}
	if _, err := io.CopyN(io.Discard, conn, int64(binary.BigEndian.Uint16(paddingBytes[:]))); err != nil {
		return
	}

	session := session.NewServerSession(conn, func(stream *session.Stream) {
		defer stream.Close()

		destination, err := M.SocksaddrSerializer.ReadAddrPort(stream)
		if err != nil {
			return
		}

		// It seems that mihomo does not implement a connection error reporting mechanism, so we report success directly.
		err = stream.HandshakeSuccess()
		if err != nil {
			return
		}

		h.NewConnection(ctx, stream, M.Metadata{
			Source:      M.SocksaddrFromNet(conn.RemoteAddr()),
			Destination: destination,
		})
	}, &l.padding)
	session.Run()
	session.Close()
}
