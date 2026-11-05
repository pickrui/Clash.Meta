package outbound

import (
	"math"
	"time"

	"github.com/metacubex/mihomo/ntp"
	"github.com/metacubex/mihomo/transport/tuic"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

func (t *Tuic) dialConfigs() (*tls.Config, *quic.Config) {
	t.configOnce.Do(func() {
		if t.tlsConfig == nil {
			t.tlsConfig = newTuicTLSConfig(t.option)
			t.tlsConfig.RootCAs = t.rootCAs
		}
		t.quicConfig = newTuicQUICConfig(t.option)
	})
	return t.tlsConfig, t.quicConfig
}

func newTuicTLSConfig(option *TuicOption) *tls.Config {
	serverName := option.Server
	if option.SNI != "" {
		serverName = option.SNI
	}
	config := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: option.SkipCertVerify,
		MinVersion:         tls.VersionTLS13,
		Time:               ntp.Now,
	}
	if option.ALPN != nil {
		config.NextProtos = option.ALPN
	} else {
		config.NextProtos = []string{"h3"}
	}
	if option.DisableSni {
		config.ServerName = ""
		config.InsecureSkipVerify = true
	}
	return config
}

func newTuicQUICConfig(option *TuicOption) *quic.Config {
	quicMaxOpenStreams := int64(option.MaxOpenStreams)
	quicMaxOpenStreams += int64(math.Ceil(float64(quicMaxOpenStreams) / 10.0))
	config := &quic.Config{
		InitialStreamReceiveWindow:     uint64(option.ReceiveWindowConn),
		MaxStreamReceiveWindow:         uint64(option.ReceiveWindowConn),
		InitialConnectionReceiveWindow: uint64(option.ReceiveWindow),
		MaxConnectionReceiveWindow:     uint64(option.ReceiveWindow),
		MaxIncomingStreams:             quicMaxOpenStreams,
		MaxIncomingUniStreams:          quicMaxOpenStreams,
		KeepAlivePeriod:                time.Duration(option.HeartbeatInterval) * time.Millisecond,
		DisablePathMTUDiscovery:        option.DisableMTUDiscovery,
		MaxDatagramFrameSize:           int64(option.MaxDatagramFrameSize),
		EnableDatagrams:                true,
	}
	if option.ReceiveWindowConn == 0 {
		config.InitialStreamReceiveWindow = tuic.DefaultStreamReceiveWindow / 10
		config.MaxStreamReceiveWindow = tuic.DefaultStreamReceiveWindow
	}
	if option.ReceiveWindow == 0 {
		config.InitialConnectionReceiveWindow = tuic.DefaultConnectionReceiveWindow / 10
		config.MaxConnectionReceiveWindow = tuic.DefaultConnectionReceiveWindow
	}
	return config
}
