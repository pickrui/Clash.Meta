package dns

import (
	"context"

	"github.com/metacubex/mihomo/component/resolver"

	D "github.com/miekg/dns"
)

func (r *Resolver) queryContext() context.Context {
	r.queryOnce.Do(func() {
		r.queryCtx, r.queryCancel = context.WithCancel(context.Background())
	})
	return r.queryCtx
}

// Queries belong to the resolver, not to any one caller sharing a question.
func (r *Resolver) CloseQueries() {
	if r == nil {
		return
	}
	r.queryContext()
	r.queryCancel()
	if r.defaultResolver != nil {
		r.defaultResolver.CloseQueries()
	}
}

func (rs Resolvers) CloseQueries() {
	rs.Resolver.CloseQueries()
	rs.ProxyResolver.CloseQueries()
	rs.DirectResolver.CloseQueries()
}

func (r *Resolver) refresh(m *D.Msg) {
	parent := r.queryContext()
	q := m.Question[0]
	r.refreshMu.Lock()
	if _, pending := r.refreshing[q]; pending || parent.Err() != nil {
		r.refreshMu.Unlock()
		return
	}
	if r.refreshing == nil {
		r.refreshing = make(map[D.Question]struct{})
	}
	r.refreshing[q] = struct{}{}
	r.refreshMu.Unlock()
	m = m.Copy()
	go func() {
		defer func() {
			r.refreshMu.Lock()
			delete(r.refreshing, q)
			if len(r.refreshing) == 0 {
				r.refreshing = nil
			}
			r.refreshMu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(parent, resolver.DefaultDNSTimeout)
		defer cancel()
		_, _ = r.exchangeWithoutCache(ctx, m)
	}()
}
