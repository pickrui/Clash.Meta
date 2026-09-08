package geodata

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/metacubex/mihomo/component/geodata/router"
	"google.golang.org/protobuf/proto"
)

func TestDownloadPreservesExistingDataOnInvalidResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("<html>challenge</html>")) }))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "geoip.dat")
	if err := os.WriteFile(path, []byte("previous"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := downloadToPath(server.URL, path); err == nil {
		t.Fatal("HTML accepted")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "previous" {
		t.Fatalf("file=%q", data)
	}
}

func TestGeoValidatorsDecodeCompleteRecords(t *testing.T) {
	malformed := []byte{0x0a, 1, 0xff}
	if err := VerifyGeoIPBytes(malformed); err == nil {
		t.Fatal("malformed GeoIP record accepted")
	}
	if err := VerifyGeoSiteBytes(malformed); err == nil {
		t.Fatal("malformed GeoSite record accepted")
	}
	data, _ := proto.Marshal(&router.GeoIPList{Entry: []*router.GeoIP{{CountryCode: "test", Cidr: []*router.CIDR{{Ip: []byte{1, 2, 3, 4}, Prefix: 24}}}}})
	if err := VerifyGeoIPBytes(data); err != nil {
		t.Fatal(err)
	}
	data, _ = proto.Marshal(&router.GeoSiteList{Entry: []*router.GeoSite{{CountryCode: "test", Domain: []*router.Domain{{Type: router.Domain_Domain, Value: "example.com"}}}}})
	if err := VerifyGeoSiteBytes(data); err != nil {
		t.Fatal(err)
	}
}

func TestMMDBValidationKeepsReadableMetadataCompatibility(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "mmdb", "testdata", "geoip-cn.mmdb"))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyMMDBBytes(data); err != nil {
		t.Fatalf("readable database rejected: %v", err)
	}
	corrupt := append([]byte{}, data...)
	for index := range 6 {
		corrupt[index] = 0xff
	}
	if err := VerifyMMDBBytes(corrupt); err == nil {
		t.Fatal("corrupt search-tree pointers accepted")
	}
}
