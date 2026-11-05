package statistic

import (
	"net/netip"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestTrackerMetadataProcessesCopy(t *testing.T) {
	previous := MetadataProcessor
	MetadataProcessor = func(metadata *C.Metadata) {
		metadata.Host = "masked"
		metadata.DstIP = netip.Addr{}
	}
	t.Cleanup(func() { MetadataProcessor = previous })
	original := &C.Metadata{
		Host:  "example.com",
		DstIP: netip.MustParseAddr("192.0.2.1"),
	}

	processed := trackerMetadata(original, "198.51.100.1:443")

	if original.Host != "example.com" || original.DstIP.String() != "192.0.2.1" || original.RemoteDst != "" {
		t.Fatalf("original metadata was modified: %+v", original)
	}
	if processed == original || processed.Host != "masked" || processed.DstIP.IsValid() {
		t.Fatalf("tracker metadata was not processed independently: %+v", processed)
	}
	if processed.RemoteDst != "198.51.100.1:443" {
		t.Fatalf("tracker remote destination = %q", processed.RemoteDst)
	}
}
