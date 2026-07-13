package provider

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
)

type countingHealthCheckProxy struct {
	C.Proxy
	calls atomic.Int32
}

func (p *countingHealthCheckProxy) Name() string {
	return "counting"
}

func (p *countingHealthCheckProxy) URLTest(
	context.Context,
	string,
	utils.IntRanges[uint16],
) (uint16, error) {
	p.calls.Add(1)
	return 1, nil
}

func (p *countingHealthCheckProxy) AliveForTestUrl(string) bool {
	return true
}

func (p *countingHealthCheckProxy) LastDelayForTestUrl(string) uint16 {
	return 1
}

func TestHealthCheckSuspendedBlocksManualChecks(t *testing.T) {
	proxy := &countingHealthCheckProxy{}
	healthCheck := NewHealthCheck(
		[]C.Proxy{proxy},
		"https://example.com/generate_204",
		1000,
		0,
		false,
		nil,
	)
	t.Cleanup(func() {
		SetHealthCheckSuspended(false)
		healthCheck.close()
	})

	SetHealthCheckSuspended(true)
	healthCheck.check()
	if got := proxy.calls.Load(); got != 0 {
		t.Fatalf("suspended health check calls = %d", got)
	}

	SetHealthCheckSuspended(false)
	healthCheck.check()
	if got := proxy.calls.Load(); got != 1 {
		t.Fatalf("active health check calls = %d", got)
	}
}
