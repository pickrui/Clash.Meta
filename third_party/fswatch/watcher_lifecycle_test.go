package fswatch

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
)

func TestNestedDirectoriesBothReceiveUpdates(t *testing.T) {
	directory := t.TempDir()
	nested := filepath.Join(directory, "keys")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	paths := []string{filepath.Join(directory, "certificate"), filepath.Join(nested, "private-key")}
	for _, path := range paths {
		if err := os.WriteFile(path, []byte("initial"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	updates := make(chan string, 8)
	watcher, err := NewWatcher(Options{
		Path:        paths,
		WaitTimeout: time.Millisecond,
		Callback:    func(path string) { updates <- path },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := watcher.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = watcher.Close() })
	for _, path := range paths {
		if err := os.WriteFile(path, []byte("updated"), 0o600); err != nil {
			t.Fatal(err)
		}
		timeout := time.After(time.Second)
	wait:
		for {
			select {
			case updated := <-updates:
				if updated == path {
					break wait
				}
			case <-timeout:
				t.Fatalf("update to %s was not observed", path)
			}
		}
	}
}

func TestLoopShutdownCancelsPendingCallbacks(t *testing.T) {
	const path = "/provider"
	events := make(chan fsnotify.Event)
	updates := make(chan string, 1)
	watcher := &Watcher{
		watchPath:   []string{path},
		waitTimeout: 30 * time.Millisecond,
		callback:    func(path string) { updates <- path },
		watcher:     &fsnotify.Watcher{Events: events, Errors: make(chan error)},
	}
	stopped := make(chan struct{})
	go func() { watcher.loopUpdate(); close(stopped) }()
	events <- fsnotify.Event{Name: path, Op: fsnotify.Write}
	close(events)
	<-stopped
	select {
	case <-updates:
		t.Fatal("pending callback ran after the watcher loop stopped")
	case <-time.After(60 * time.Millisecond):
	}
}
