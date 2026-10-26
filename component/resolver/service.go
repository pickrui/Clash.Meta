package resolver

import (
	"context"

	"github.com/metacubex/mihomo/common/atomic"

	D "github.com/miekg/dns"
)

var DefaultService atomic.TypedValue[Service]

type Service interface {
	ServeMsg(ctx context.Context, msg *D.Msg) (*D.Msg, error)
}

// ServeMsg with a dns.Msg, return resolve dns.Msg
func ServeMsg(ctx context.Context, msg *D.Msg) (*D.Msg, error) {
	if server := DefaultService.Load(); server != nil {
		return server.ServeMsg(ctx, msg)
	}

	return nil, ErrIPNotFound
}
