package updater

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/mmdb"
	C "github.com/metacubex/mihomo/constant"
)

func TestUpdateMappedDatabasesPreservesActiveReaders(t *testing.T) {
	oldHome, oldMMDBURL, oldASNURL := C.Path.HomeDir(), geodata.MmdbUrl(), geodata.ASNUrl()
	C.SetHomeDir(t.TempDir())
	mmdb.ReloadIP()
	mmdb.ReloadASN()
	t.Cleanup(func() {
		mmdb.ReloadIP()
		mmdb.ReloadASN()
		C.SetHomeDir(oldHome)
		geodata.SetMmdbUrl(oldMMDBURL)
		geodata.SetASNUrl(oldASNURL)
	})
	fixture := func(name string) []byte {
		t.Helper()
		data, err := os.ReadFile(filepath.Join("..", "mmdb", "testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	if err := os.WriteFile(C.Path.MMDB(), fixture("geoip-cn.mmdb"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(C.Path.ASN(), fixture("asn-64512.mmdb"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldIP, oldASN := mmdb.IPInstance(), mmdb.ASNInstance()
	newIPData, newASNData := fixture("geoip-us.mmdb"), fixture("asn-64513.mmdb")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mmdb" {
			_, _ = w.Write(newIPData)
		} else {
			_, _ = w.Write(newASNData)
		}
	}))
	defer server.Close()
	geodata.SetMmdbUrl(server.URL + "/mmdb")
	geodata.SetASNUrl(server.URL + "/asn")
	if err := UpdateMMDB(); err != nil {
		t.Fatal(err)
	}
	if err := UpdateASN(); err != nil {
		t.Fatal(err)
	}
	ip := net.IPv4(1, 2, 3, 4)
	if got := mmdb.IPInstance().LookupCode(ip); len(got) != 1 || got[0] != "us" {
		t.Fatalf("new country = %v, want [us]", got)
	}
	if got := oldIP.LookupCode(ip); len(got) != 1 || got[0] != "cn" {
		t.Fatalf("old country = %v, want [cn]", got)
	}
	if got, _ := mmdb.ASNInstance().LookupASN(ip); got != "64513" {
		t.Fatalf("new ASN = %s, want 64513", got)
	}
	if got, _ := oldASN.LookupASN(ip); got != "64512" {
		t.Fatalf("old ASN = %s, want 64512", got)
	}
}

func TestWriteGeoDatabaseFailurePreservesTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "database.mmdb")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(path, "keep")
	if err := os.WriteFile(marker, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeGeoDatabase(path, []byte("replacement")); err == nil {
		t.Fatal("replacement of a directory succeeded")
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "existing" {
		t.Fatalf("failed replacement changed its target: %q, %v", data, err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatalf("failed replacement left temporary files: %v, %v", entries, err)
	}
}
