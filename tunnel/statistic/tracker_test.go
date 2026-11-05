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

type trafficTestConn struct {
	C.Conn
	name string
}

func (c trafficTestConn) Chains() C.Chain             { return C.Chain{c.name} }
func (c trafficTestConn) ProviderChains() C.Chain     { return nil }
func (c trafficTestConn) RemoteDestination() string   { return "" }
func (c trafficTestConn) Write(p []byte) (int, error) { return len(p), nil }

func TestTrackerCachesDirectClassification(t *testing.T) {
	previous := IsDirect
	defer func() { IsDirect = previous }()
	IsDirect = func(name string) bool { return name == "custom-direct" }
	manager := &Manager{}
	direct := NewTCPTracker(trafficTestConn{name: "custom-direct"}, manager, &C.Metadata{}, nil, 10, 20, true)
	proxy := NewTCPTracker(trafficTestConn{name: "DIRECT"}, manager, &C.Metadata{}, nil, 30, 40, true)
	IsDirect = func(string) bool { t.Fatal("classification repeated during transfer"); return false }
	_, _ = direct.Write([]byte{1, 2})
	_, _ = proxy.Write([]byte{1, 2, 3})
	if up, down := manager.TotalTraffic(true); up != 33 || down != 40 {
		t.Fatalf("proxy traffic=%d/%d", up, down)
	}
	if up, down := manager.TotalTraffic(false); up != 45 || down != 60 {
		t.Fatalf("total traffic=%d/%d", up, down)
	}
}
