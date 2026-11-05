package fswatch_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/metacubex/fswatch"

	"github.com/stretchr/testify/require"
)

func TestFileWatcher(t *testing.T) {
	t.Parallel()
	tempDir, err := os.MkdirTemp("", "file-watcher-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)
	watchPath := filepath.Join(tempDir, "test")
	fileContent := "Hello world!"
	done := make(chan struct{})
	watcher, err := fswatch.NewWatcher(fswatch.Options{
		Path: []string{watchPath},
		Callback: func(path string) {
			newContent, err := os.ReadFile(watchPath)
			require.NoError(t, err)
			require.Equal(t, fileContent, string(newContent))
			close(done)
		},
	})
	require.NoError(t, err)
	defer watcher.Close()
	require.NoError(t, watcher.Start())
	file, err := os.Create(watchPath)
	require.NoError(t, err)
	_, err = file.WriteString(fileContent)
	require.NoError(t, err)
	require.NoError(t, file.Close())
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("watch timeout")
	}
	done = make(chan struct{})
	require.NoError(t, os.Remove(watchPath))
	tempPath := filepath.Join(tempDir, "temp")
	require.NoError(t, os.WriteFile(tempPath, []byte(fileContent), 0o644))
	require.NoError(t, os.Rename(tempPath, watchPath))
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("watch timeout")
	}
	done = make(chan struct{})
	require.NoError(t, os.Remove(watchPath))
	require.NoError(t, os.WriteFile(tempPath, []byte(fileContent), 0o644))
	select {
	case <-done:
		t.Fatal("invalid event")
	case <-time.After(1 * time.Second):
	}
}

func TestWatchDirect(t *testing.T) {
	t.Parallel()
	tempDir, err := os.MkdirTemp("", "file-watcher-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)
	watchPath := filepath.Join(tempDir, "test")
	file, err := os.Create(watchPath)
	require.NoError(t, err)
	_, err = file.WriteString("")
	require.NoError(t, err)
	require.NoError(t, file.Close())
	fileContent := "Hello world!"
	done := make(chan struct{})
	watcher, err := fswatch.NewWatcher(fswatch.Options{
		Path:   []string{watchPath},
		Direct: true,
		Callback: func(path string) {
			newContent, err := os.ReadFile(watchPath)
			require.NoError(t, err)
			require.Equal(t, fileContent, string(newContent))
			close(done)
		},
	})
	require.NoError(t, err)
	defer watcher.Close()
	require.NoError(t, watcher.Start())
	file, err = os.Create(watchPath)
	require.NoError(t, err)
	_, err = file.WriteString(fileContent)
	require.NoError(t, err)
	require.NoError(t, file.Close())
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("watch timeout")
	}
	done = make(chan struct{})
	tempPath := filepath.Join(tempDir, "temp")
	require.NoError(t, os.WriteFile(tempPath, []byte(fileContent), 0o644))
	require.NoError(t, os.Rename(tempPath, watchPath))
	select {
	case <-done:
		if runtime.GOOS != "darwin" {
			t.Fatal("invalid event")
		}
	case <-time.After(1 * time.Second):
		if runtime.GOOS == "darwin" {
			t.Fatal("watch timeout")
		}
	}
}

func TestStartFailureReleasesResources(t *testing.T) {
	valid := t.TempDir()
	missing := filepath.Join(t.TempDir(), "missing")
	watcher, err := fswatch.NewWatcher(fswatch.Options{
		Path:     []string{valid, missing},
		Direct:   true,
		Callback: func(string) {},
	})
	require.NoError(t, err)
	defer watcher.Close()
	before := runtime.NumGoroutine()
	for attempt := 0; attempt < 16; attempt++ {
		require.ErrorIs(t, watcher.Start(), os.ErrNotExist)
	}
	deadline := time.Now().Add(time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	require.LessOrEqual(t, runtime.NumGoroutine(), before, "failed starts left watcher goroutines running")

	require.NoError(t, os.Mkdir(missing, 0o700))
	require.NoError(t, watcher.Start())
}
