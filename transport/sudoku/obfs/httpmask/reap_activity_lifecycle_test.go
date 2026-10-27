package httpmask

import (
	"bytes"
	"runtime"
	"testing"
	"time"
)

func TestReaperRechecksActivityAfterPullContention(t *testing.T) {
	const token = "touched-before-reaper-commit"
	app, peer := newHalfPipe()
	server := NewTunnelServer(TunnelServerOptions{SessionTTL: time.Hour})
	sess := server.sessionAdd(token, peer)
	sess.reaper.Stop()
	server.mu.Lock()
	sess.lastActive = time.Now().Add(-2 * time.Hour)
	server.mu.Unlock()
	sess.pullMu.Lock()
	locked := true
	done := make(chan struct{})
	var removed bool
	go func() { _, removed = server.reapIfIdle(token, sess); close(done) }()
	defer func() {
		if locked {
			sess.pullMu.Unlock()
		}
		<-done
		server.sessionClose(token)
		app.Close()
		peer.Close()
	}()
	deadline := time.Now().Add(time.Second)
	for {
		stacks := make([]byte, 64<<10)
		n := runtime.Stack(stacks, true)
		blocked := false
		for _, stack := range bytes.Split(stacks[:n], []byte("\n\n")) {
			if bytes.Contains(stack, []byte(".reapIfIdle(")) && bytes.Contains(stack, []byte("[sync.Mutex.Lock]")) {
				blocked = true
				break
			}
		}
		if blocked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("reaper did not block on the held pull lock")
		}
		runtime.Gosched()
	}
	if !server.sessionTouch(token, sess) {
		t.Fatal("session disappeared before activity update")
	}
	sess.pullMu.Unlock()
	locked = false
	<-done
	if removed || !server.sessionHas(token) {
		t.Fatal("reaper removed a session touched while it waited for pull ownership")
	}
}
