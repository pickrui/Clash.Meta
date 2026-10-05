package geodata

import (
	"sync"
	"testing"
)

func TestResourceURLsConcurrentAccess(t *testing.T) {
	resources := []struct {
		get func() string
		set func(string)
	}{
		{GeoIpUrl, SetGeoIpUrl}, {MmdbUrl, SetMmdbUrl},
		{GeoSiteUrl, SetGeoSiteUrl}, {ASNUrl, SetASNUrl},
	}
	for _, resource := range resources {
		previous := resource.get()
		t.Cleanup(func() { resource.set(previous) })
		const first = "https://example.test/geo.dat"
		const second = "https://mirror.example.test/updated/geo.dat"
		resource.set(first)
		var workers sync.WaitGroup
		for worker := 0; worker < 4; worker++ {
			workers.Go(func() {
				for iteration := 0; iteration < 1000; iteration++ {
					resource.set(first)
					if value := resource.get(); value != first && value != second {
						t.Errorf("incomplete resource URL: %q", value)
						return
					}
					resource.set(second)
				}
			})
		}
		workers.Wait()
	}
}
