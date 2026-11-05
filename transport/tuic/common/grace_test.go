package common

import (
	"runtime"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestGraceDeadlineAndMissingReferences(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		owner, session := new(atomic.Int64), new(atomic.Int64)
		session.Store(1)
		release := func(owner, session *atomic.Int64) {
			owner.Add(1)
			session.Add(-1)
		}
		AfterGrace(5*time.Second, owner, session, release)
		AfterGrace(5*time.Second, nil, session, release)
		AfterGrace(5*time.Second, owner, nil, release)
		time.Sleep(5*time.Second - time.Nanosecond)
		if owner.Load() != 0 || session.Load() != 1 {
			t.Fatal("the stream slot was released before its grace period")
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		if owner.Load() != 1 || session.Load() != 0 {
			t.Fatal("the live stream slot was not released exactly once")
		}
		runtime.KeepAlive(owner)
		runtime.KeepAlive(session)
	})
}
