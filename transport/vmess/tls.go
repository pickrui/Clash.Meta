package vmess

import (
	"context"
	"errors"
	"net"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	tlsC "github.com/metacubex/mihomo/component/tls"

	"github.com/metacubex/tls"
	utls "github.com/metacubex/utls"
)

type TLSConfig struct {
	Host                 string
	SkipCertVerify       bool
	CAFile               string
	FingerPrint          string
	Certificate          string
	PrivateKey           string
	ClientFingerprint    string
	NextProtos           []string
	ECH                  *ech.Config
	Reality              *tlsC.RealityConfig
	ClientSessionCache   tls.ClientSessionCache
	UClientSessionCache  utls.ClientSessionCache
	DisableRenegotiation bool
}

func (cfg *TLSConfig) ToStdConfig() (*tls.Config, error) {
	tlsConfig, err := ca.GetTLSConfig(ca.Option{
		TLSConfig: &tls.Config{
			ServerName:         cfg.Host,
			InsecureSkipVerify: cfg.SkipCertVerify,
			NextProtos:         cfg.NextProtos,
			ClientSessionCache: cfg.ClientSessionCache,
		},
		Fingerprint: cfg.FingerPrint,
		Certificate: cfg.Certificate,
		PrivateKey:  cfg.PrivateKey,
	})
	if err != nil {
		return nil, err
	}
	if cfg.CAFile != "" {
		tlsConfig.RootCAs, err = ca.LoadCertificates(cfg.CAFile)
		if err != nil {
			return nil, err
		}
	}
	return tlsConfig, nil
}

func StreamTLSConn(ctx context.Context, conn net.Conn, cfg *TLSConfig) (net.Conn, error) {
	tlsConfig, err := cfg.ToStdConfig()
	if err != nil {
		return nil, err
	}

	if clientFingerprint, ok := tlsC.GetFingerprint(cfg.ClientFingerprint); ok {
		if cfg.Reality != nil {
			return tlsC.GetRealityConn(ctx, conn, clientFingerprint, tlsConfig.ServerName, cfg.Reality)
		}
		tlsConfig := tlsC.UConfig(tlsConfig)
		tlsConfig.ClientSessionCache = cfg.UClientSessionCache
		err = cfg.ECH.ClientHandleUTLS(ctx, tlsConfig)
		if err != nil {
			return nil, err
		}
		tlsConn := tlsC.UClient(conn, tlsConfig, clientFingerprint)
		if cfg.DisableRenegotiation {
			if err = tlsConn.BuildHandshakeState(); err != nil {
				return nil, err
			}
			for _, extension := range tlsConn.Extensions {
				if renegotiation, ok := extension.(*utls.RenegotiationInfoExtension); ok {
					renegotiation.Renegotiation = utls.RenegotiateNever
				}
			}
		}
		err = tlsConn.HandshakeContext(ctx)
		if err != nil {
			return nil, err
		}
		return tlsConn, nil
	}
	if cfg.Reality != nil {
		return nil, errors.New("REALITY is based on uTLS, please set a client-fingerprint")
	}

	err = cfg.ECH.ClientHandle(ctx, tlsConfig)
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(conn, tlsConfig)

	err = tlsConn.HandshakeContext(ctx)
	return tlsConn, err
}
