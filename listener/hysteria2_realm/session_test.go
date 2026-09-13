package hysteria2_realm

import (
	"context"
	"testing"
	"time"
)

func TestReaperExitsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { (&server{}).reaper(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("reaper did not exit after cancellation")
	}
}
