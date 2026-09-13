package restls

import (
	"context"
	"net"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/ntp"

	tls "github.com/metacubex/restls-client-go"
)

const (
	Mode string = "restls"
)

type Restls struct {
	*tls.UConn
}

func (r *Restls) Upstream() any {
	return r.UConn.NetConn()
}

type Config = tls.Config

func NewRestlsConfig(serverName, password, versionHint, restlsScript, clientID string) (*Config, error) {
	config, err := tls.NewRestlsConfig(serverName, password, versionHint, restlsScript, clientID)
	if err != nil {
		return nil, err
	}
	config.RootCAs = ca.GetCertPool()
	config.Time = ntp.Now
	return config, nil
}

// NewRestls return a Restls Connection
func NewRestls(ctx context.Context, conn net.Conn, config *Config) (net.Conn, error) {
	clientHellowID := tls.HelloChrome_Auto
	if config != nil {
		clientIDPtr := config.ClientID.Load()
		if clientIDPtr != nil {
			clientHellowID = *clientIDPtr
		}
	}
	restls := &Restls{
		UConn: tls.UClient(conn, config, clientHellowID),
	}
	if err := restls.HandshakeContext(ctx); err != nil {
		return nil, err
	}

	return restls, nil
}
