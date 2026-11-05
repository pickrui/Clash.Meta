package geodata

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"weak"

	"github.com/metacubex/mihomo/component/geodata/router"
)

type retentionLoader struct {
	LoaderImplementation
	load func() ([]*router.Domain, error)
}

func (l retentionLoader) LoadSiteByPath(_, _ string) ([]*router.Domain, error) {
	return l.load()
}

func stageRetentionLoader(t testing.TB, name, matcher string, load func() ([]*router.Domain, error)) {
	t.Helper()
	previousLoader, previousMatcher := geoLoaderName, geoSiteMatcher
	previousFactory, existed := loaders[name]
	ClearGeoSiteCache()
	RegisterGeoDataLoaderImplementationCreator(name, func() LoaderImplementation {
		return retentionLoader{load: load}
	})
	SetLoader(name)
	SetSiteMatcher(matcher)
	t.Cleanup(func() {
		ClearGeoSiteCache()
		geoLoaderName, geoSiteMatcher = previousLoader, previousMatcher
		if existed {
			loaders[name] = previousFactory
		} else {
			delete(loaders, name)
		}
	})
}

func TestGeoSiteSourceRetentionAndMatching(t *testing.T) {
	for _, loader := range []string{"memconservative", "standard"} {
		for _, algorithm := range []string{"succinct", "mph"} {
			t.Run(loader+"/"+algorithm, func(t *testing.T) {
				reads := 0
				var source weak.Pointer[router.Domain]
				stageRetentionLoader(t, loader, algorithm, func() ([]*router.Domain, error) {
					reads++
					ads := []*router.Domain_Attribute{{Key: "ads"}}
					domains := []*router.Domain{
						{Type: router.Domain_Full, Value: "exact.example"},
						{Type: router.Domain_Domain, Value: "suffix.example", Attribute: ads},
						{Type: router.Domain_Plain, Value: "tracker", Attribute: ads},
						{Type: router.Domain_Regex, Value: `^regex[0-9]+\.example$`, Attribute: ads},
					}
					source = weak.Make(domains[0])
					return domains, nil
				})
				base, err := LoadGeoSiteMatcher("retention")
				if err != nil {
					t.Fatal(err)
				}
				runtime.GC()
				if retained := source.Value() != nil; retained != (loader == "standard") {
					t.Fatalf("decoded source retained = %v for %s", retained, loader)
				}
				again, err := LoadGeoSiteMatcher("RETENTION")
				if err != nil || again != base || reads != 1 {
					t.Fatalf("cached matcher was not reused: reads=%d, err=%v", reads, err)
				}
				filtered, err := LoadGeoSiteMatcher("retention@ads")
				if err != nil {
					t.Fatal(err)
				}
				inverted, err := LoadGeoSiteMatcher("!retention@ads")
				if err != nil {
					t.Fatal(err)
				}
				wantReads := 1
				if loader == "memconservative" {
					wantReads = 2
				}
				if reads != wantReads || base.Count() != 4 || filtered.Count() != 3 {
					t.Fatalf("reads=%d, counts=%d/%d", reads, base.Count(), filtered.Count())
				}
				for host, wantFiltered := range map[string]bool{
					"exact.example": false, "www.suffix.example": true,
					"mytracker.example": true, "regex7.example": true, "miss.example": false,
				} {
					if base.ApplyDomain(host) != (wantFiltered || host == "exact.example") ||
						filtered.ApplyDomain(host) != wantFiltered || inverted.ApplyDomain(host) == wantFiltered {
						t.Errorf("incorrect matching for %q", host)
					}
				}
				ClearGeoSiteCache()
				if _, err := LoadGeoSiteMatcher("retention"); err != nil || reads != wantReads+1 {
					t.Fatalf("cache invalidation did not reload: reads=%d, err=%v", reads, err)
				}
			})
		}
	}
}

func TestGeoSiteRetryAndConcurrentReuse(t *testing.T) {
	for _, loader := range []string{"memconservative", "standard"} {
		t.Run(loader, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				release := make(chan struct{})
				var reads atomic.Int32
				stageRetentionLoader(t, loader, "succinct", func() ([]*router.Domain, error) {
					switch reads.Add(1) {
					case 1:
						<-release
						return nil, fmt.Errorf("temporary read failure")
					case 2:
						if loader == "memconservative" {
							return []*router.Domain{{Type: router.Domain_Regex, Value: "["}}, nil
						}
					}
					return []*router.Domain{{Type: router.Domain_Full, Value: "recovered.example"}}, nil
				})
				var wg sync.WaitGroup
				for range 4 {
					wg.Go(func() {
						if _, err := LoadGeoSiteMatcher("retry"); err == nil {
							t.Error("failed read accepted")
						}
					})
				}
				synctest.Wait()
				close(release)
				wg.Wait()
				wantReads := int32(2)
				if loader == "memconservative" {
					if _, err := LoadGeoSiteMatcher("retry"); err == nil {
						t.Fatal("invalid source accepted")
					}
					wantReads = 3
				}
				for range 32 {
					wg.Go(func() {
						matcher, err := LoadGeoSiteMatcher("retry")
						if err != nil {
							t.Error(err)
							return
						}
						if !matcher.ApplyDomain("recovered.example") {
							t.Error("reloaded source did not match")
						}
					})
				}
				wg.Wait()
				if reads.Load() != wantReads {
					t.Fatalf("read source %d times, want %d including the failures", reads.Load(), wantReads)
				}
			})
		})
	}
}
