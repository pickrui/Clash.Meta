package adapter

import (
	"context"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
)

type backgroundURLTestKey struct{}

func WithBackgroundURLTest(ctx context.Context) context.Context {
	return context.WithValue(ctx, backgroundURLTestKey{}, true)
}

type urlTestKey struct {
	url, expected string
	background    bool
	unified       bool
}

type urlTestFlight struct {
	done  chan struct{}
	delay uint16
	err   error
	retry bool
}

type urlTestFlights struct {
	mu      sync.Mutex
	running map[urlTestKey]*urlTestFlight
}

func (p *Proxy) URLTest(ctx context.Context, url string, expected utils.IntRanges[uint16]) (uint16, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	switch p.Type() {
	case C.Relay, C.Selector, C.Fallback, C.URLTest, C.LoadBalance:
		return p.urlTestOnce(ctx, url, expected)
	}
	background, _ := ctx.Value(backgroundURLTestKey{}).(bool)
	key := urlTestKey{url, expected.String(), background, UnifiedDelay.Load()}
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		p.urlTests.mu.Lock()
		flight := p.urlTests.running[key]
		if flight == nil {
			flight = &urlTestFlight{done: make(chan struct{}), retry: true}
			if p.urlTests.running == nil {
				p.urlTests.running = make(map[urlTestKey]*urlTestFlight)
			}
			p.urlTests.running[key] = flight
			p.urlTests.mu.Unlock()
			return p.leadURLTest(ctx, key, flight, expected)
		}
		p.urlTests.mu.Unlock()
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-flight.done:
			if err := ctx.Err(); err != nil {
				return 0, err
			}
			// Another caller's cancellation or shorter deadline must not decide
			// this caller's result. Only the actual probe publishes health state.
			if !flight.retry {
				return flight.delay, flight.err
			}
		}
	}
}

func (p *Proxy) leadURLTest(ctx context.Context, key urlTestKey, flight *urlTestFlight, expected utils.IntRanges[uint16]) (uint16, error) {
	defer func() {
		p.urlTests.mu.Lock()
		delete(p.urlTests.running, key)
		if len(p.urlTests.running) == 0 {
			p.urlTests.running = nil
		}
		close(flight.done)
		p.urlTests.mu.Unlock()
	}()
	flight.delay, flight.err = p.urlTestOnce(ctx, key.url, expected)
	flight.retry = flight.err != nil && ctx.Err() != nil
	return flight.delay, flight.err
}

func (p *Proxy) URLTestSucceededSince(url, expected string, timeout time.Duration, since time.Time) bool {
	switch p.Type() {
	case C.Relay, C.Selector, C.Fallback, C.URLTest, C.LoadBalance:
		return false
	}
	p.testMu.Lock()
	defer p.testMu.Unlock()
	state, ok := p.extra.Load(url)
	if !ok || !state.alive.Load() || state.expected != expected {
		return false
	}
	record := state.history.Last()
	return !record.Time.Before(since) && record.Delay > 0 && time.Duration(record.Delay)*time.Millisecond <= timeout
}
