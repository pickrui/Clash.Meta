package tunnel

import (
	"context"
	"fmt"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

var _ C.RuleDialer = Tunnel

func (t tunnel) DialTCPByRules(ctx context.Context, metadata *C.Metadata, check func(C.Proxy, C.Rule) error) (C.Conn, error) {
	metadata.NetWork = C.TCP
	metadata.Type = C.INNER
	metadata.Process = C.MihomoName
	proxy, rule, err := resolveMetadata(metadata)
	if err != nil {
		return nil, err
	}
	if proxy == nil {
		return nil, fmt.Errorf("no proxy for %s", metadata.RemoteAddress())
	}
	if err = check(proxy, rule); err != nil {
		return nil, err
	}
	conn, err := proxy.DialContext(ctx, metadata)
	if err != nil {
		logMetadataErr(metadata, rule, proxy, err)
		return nil, err
	}
	logMetadata(metadata, rule, conn)
	return statistic.NewTCPTracker(conn, statistic.DefaultManager, metadata, rule, 0, 0, false), nil
}
