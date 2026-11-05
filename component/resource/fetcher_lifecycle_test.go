package resource

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	P "github.com/metacubex/mihomo/constant/provider"
)

type blockingWriteVehicle struct {
	started chan struct{}
	release chan struct{}
	writes  atomic.Int32
}

func (v *blockingWriteVehicle) Type() P.VehicleType { return P.HTTP }
func (v *blockingWriteVehicle) Path() string        { return "unused" }
func (v *blockingWriteVehicle) Url() string         { return "unused" }
func (v *blockingWriteVehicle) Proxy() string       { return "" }
func (v *blockingWriteVehicle) Read(context.Context, utils.HashType) ([]byte, utils.HashType, error) {
	data := []byte("valid")
	return data, utils.MakeHash(data), nil
}
func (v *blockingWriteVehicle) Write([]byte) error {
	v.writes.Add(1)
	if v.started != nil {
		close(v.started)
		<-v.release
	}
	return nil
}

func TestFetcherCloseAndWaitDrainsInFlightWork(t *testing.T) {
	for _, phase := range []string{"parser", "write"} {
		t.Run(phase, func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
			vehicle := &blockingWriteVehicle{}
			if phase == "write" {
				vehicle.started = started
				vehicle.release = release
			}
			var published atomic.Int32
			fetcher := NewFetcher("test", 0, vehicle, nil, func(data []byte) (string, error) {
				if phase == "parser" {
					close(started)
					<-release
				}
				return string(data), nil
			}, func(string) { published.Add(1) })
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }); _ = fetcher.Close(); fetcher.WaitForUpdates() })
			updated := make(chan error, 1)
			go func() { _, _, err := fetcher.Update(); updated <- err }()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("update did not start")
			}
			_ = fetcher.Close()
			drained := make(chan struct{})
			go func() { fetcher.WaitForUpdates(); close(drained) }()
			select {
			case <-drained:
				t.Fatal("retirement finished with work still in flight")
			case <-time.After(20 * time.Millisecond):
			}
			releaseOnce.Do(func() { close(release) })
			select {
			case <-drained:
			case <-time.After(time.Second):
				t.Fatal("retirement did not drain")
			}
			if err := <-updated; !errors.Is(err, context.Canceled) {
				t.Fatalf("update error = %v", err)
			}
			if published.Load() != 0 {
				t.Fatal("closed provider published an update")
			}
			before := vehicle.writes.Load()
			if _, _, err := fetcher.Update(); !errors.Is(err, context.Canceled) {
				t.Fatalf("retired update error = %v", err)
			}
			if _, _, err := fetcher.SideUpdate([]byte("later")); !errors.Is(err, context.Canceled) {
				t.Fatalf("retired import error = %v", err)
			}
			if vehicle.writes.Load() != before {
				t.Fatal("retired provider wrote again")
			}
		})
	}
}

func TestFetcherMetadataDuringUpdate(t *testing.T) {
	fetcher := NewFetcher("test", 0, NewFileVehicle(filepath.Join(t.TempDir(), "provider")), nil, func(data []byte) (string, error) { return string(data), nil }, nil)
	defer fetcher.Close()
	var group sync.WaitGroup
	group.Go(func() {
		for range 1000 {
			if _, _, err := fetcher.SideUpdate([]byte("valid")); err != nil {
				t.Error(err)
			}
		}
	})
	group.Go(func() {
		for range 1000 {
			_ = fetcher.UpdatedAt()
		}
	})
	group.Wait()
	if fetcher.UpdatedAt().IsZero() {
		t.Fatal("update time not published")
	}
}
