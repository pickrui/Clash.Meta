package resource

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestReplaceFilePreservesRevisionsAndRollsBack(t *testing.T) {
	dir := t.TempDir()
	old, next := filepath.Join(dir, "old"), filepath.Join(dir, "next")
	for path, data := range map[string]string{old: "old", next: "next"} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var value atomic.Value
	var discarded atomic.Int32
	f := NewFetcher("local", 0, NewFileVehicle(old), nil, func(data []byte) (string, error) {
		if string(data) == "invalid" {
			return "", errors.New("invalid content")
		}
		return string(data), nil
	}, func(v string) { value.Store(v) })
	f.SetDiscard(func(string) { discarded.Add(1) })
	t.Cleanup(func() { _ = f.Close(); f.WaitForUpdates() })
	if _, err := f.Initial(); err != nil {
		t.Fatal(err)
	}
	if err := f.ReplaceFile(old, next, []byte("old"), []byte("next")); err != nil {
		t.Fatal(err)
	}
	if f.Vehicle().Path() != next || value.Load() != "next" {
		t.Fatal("new revision not active")
	}
	if data, _ := os.ReadFile(old); string(data) != "old" {
		t.Fatal("old cache overwritten")
	}
	if err := f.ReplaceFile(old, next, []byte("old"), []byte("next")); err == nil {
		t.Fatal("stale path accepted")
	}
	if err := f.ReplaceFile(next, old, []byte("next"), []byte("invalid")); err == nil {
		t.Fatal("invalid parse succeeded")
	}
	if err := f.ReplaceFile(next, filepath.Join(dir, "missing", "file"), []byte("next"), []byte("candidate")); err == nil {
		t.Fatal("missing watcher directory accepted")
	}
	if discarded.Load() != 1 || value.Load() != "next" || f.Vehicle().Path() != next {
		t.Fatal("failed watcher creation published a candidate")
	}
	if err := f.ReplaceFile(next, old, []byte("next"), []byte("old")); err != nil {
		t.Fatal(err)
	}
	if value.Load() != "old" || f.Vehicle().Path() != old {
		t.Fatal("rollback failed")
	}
	if data, _ := os.ReadFile(next); string(data) != "next" {
		t.Fatal("new cache overwritten by rollback")
	}
}

func TestReplaceFileConcurrentReadsAndClose(t *testing.T) {
	dir := t.TempDir()
	paths := []string{filepath.Join(dir, "a"), filepath.Join(dir, "b")}
	for _, path := range paths {
		if err := os.WriteFile(path, []byte(filepath.Base(path)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	f := NewFetcher("local", 0, NewFileVehicle(paths[0]), nil, func(data []byte) (string, error) { return string(data), nil }, nil)
	if _, err := f.Initial(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close(); f.WaitForUpdates() })
	var wg sync.WaitGroup
	for range 3 {
		wg.Go(func() {
			for range 60 {
				_ = f.Vehicle().Path()
				_, _, _ = f.Update()
				_, _ = f.ReadSnapshot(10)
			}
		})
	}
	for i := range 30 {
		a, b := paths[i%2], paths[(i+1)%2]
		if err := f.ReplaceFile(a, b, []byte(filepath.Base(a)), []byte(filepath.Base(b))); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	_ = f.Close()
	if err := f.ReplaceFile(paths[0], paths[1], []byte("a"), []byte("b")); err == nil {
		t.Fatal("retired fetcher accepted replacement")
	}
}

func TestReplaceFileWatchesNewRevisionAndRejectsConcurrentMutation(t *testing.T) {
	dir := t.TempDir()
	old, next := filepath.Join(dir, "old"), filepath.Join(dir, "next")
	for path, data := range map[string]string{old: "old", next: "next"} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var value atomic.Value
	f := NewFetcher("watch", 0, NewFileVehicle(old), nil, func(data []byte) (string, error) { return string(data), nil }, func(v string) { value.Store(v) })
	t.Cleanup(func() { _ = f.Close(); f.WaitForUpdates() })
	if _, err := f.Initial(); err != nil {
		t.Fatal(err)
	}
	if err := f.ReplaceFile(old, next, []byte("old"), []byte("next")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(next, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for value.Load() != "changed" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if value.Load() != "changed" {
		t.Fatal("replacement watcher did not publish")
	}
	if err := f.ReplaceFile(next, old, []byte("next"), []byte("old")); err == nil {
		t.Fatal("stale rollback overwrote a concurrent update")
	}
}

func TestReplaceFileClosedDuringParseDiscardsCandidate(t *testing.T) {
	dir := t.TempDir()
	old, next := filepath.Join(dir, "old"), filepath.Join(dir, "next")
	for path, data := range map[string]string{old: "old", next: "next"} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	started, release := make(chan struct{}), make(chan struct{})
	var discarded atomic.Int32
	var value atomic.Value
	f := NewFetcher("close", 0, NewFileVehicle(old), nil, func(data []byte) (string, error) {
		if string(data) == "next" {
			close(started)
			<-release
		}
		return string(data), nil
	}, func(v string) { value.Store(v) })
	f.SetDiscard(func(string) { discarded.Add(1) })
	t.Cleanup(func() { _ = f.Close(); f.WaitForUpdates() })
	if _, err := f.Initial(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- f.ReplaceFile(old, next, []byte("old"), []byte("next")) }()
	<-started
	_ = f.Close()
	close(release)
	if err := <-done; err == nil {
		t.Fatal("retired provider published")
	}
	if value.Load() != "old" || f.Vehicle().Path() != old || discarded.Load() != 1 {
		t.Fatal("retirement did not preserve old revision")
	}
}
