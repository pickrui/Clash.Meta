package mmdb

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func prepareDatabases(t *testing.T) {
	t.Helper()
	previousHome := C.Path.HomeDir()
	C.SetHomeDir(t.TempDir())
	ReloadIP()
	ReloadASN()
	t.Cleanup(func() {
		ReloadIP()
		ReloadASN()
		C.SetHomeDir(previousHome)
	})
	replaceFixture(t, C.Path.MMDB(), "geoip-cn.mmdb")
	replaceFixture(t, C.Path.ASN(), "asn-64512.mmdb")
}

func replaceFixture(t *testing.T, path, fixture string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", fixture))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".next", data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".next", path); err != nil {
		t.Fatal(err)
	}
}

func TestReloadPreservesReadersAcrossFileReplacement(t *testing.T) {
	prepareDatabases(t)
	ip := net.IPv4(1, 2, 3, 4)
	oldIP, oldASN := IPInstance(), ASNInstance()
	replaceFixture(t, C.Path.MMDB(), "geoip-us.mmdb")
	replaceFixture(t, C.Path.ASN(), "asn-64513.mmdb")
	ReloadIP()
	ReloadASN()
	newIP, newASN := IPInstance(), ASNInstance()
	if oldIP.Reader == newIP.Reader || oldASN.Reader == newASN.Reader {
		t.Fatal("reload reused a reader for the previous database")
	}
	runtime.GC()
	if got := oldIP.LookupCode(ip); len(got) != 1 || got[0] != "cn" {
		t.Fatalf("old country reader = %v, want [cn]", got)
	}
	if got := newIP.LookupCode(ip); len(got) != 1 || got[0] != "us" {
		t.Fatalf("new country reader = %v, want [us]", got)
	}
	if number, organization := oldASN.LookupASN(ip); number != "64512" || organization != "Test Network A" {
		t.Fatalf("old ASN reader = (%s, %s)", number, organization)
	}
	if number, organization := newASN.LookupASN(ip); number != "64513" || organization != "Test Network B" {
		t.Fatalf("new ASN reader = (%s, %s)", number, organization)
	}
}

func TestConcurrentReloadAndLookup(t *testing.T) {
	prepareDatabases(t)
	ip := net.IPv4(1, 2, 3, 4)
	var readers sync.WaitGroup
	failures := make(chan error, 8)
	start := make(chan struct{})
	for range 8 {
		readers.Go(func() {
			<-start
			for range 1000 {
				if got := IPInstance().LookupCode(ip); len(got) != 1 || got[0] != "cn" {
					failures <- fmt.Errorf("country lookup = %v, want [cn]", got)
					return
				}
				if number, _ := ASNInstance().LookupASN(ip); number != "64512" {
					failures <- fmt.Errorf("ASN lookup = %s, want 64512", number)
					return
				}
			}
		})
	}
	close(start)
	for range 100 {
		ReloadIP()
		ReloadASN()
		runtime.Gosched()
	}
	readers.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
}

func TestLoadFromBytesPreservesCurrentGeneration(t *testing.T) {
	prepareDatabases(t)
	current := IPInstance()
	data, err := os.ReadFile(filepath.Join("testdata", "geoip-us.mmdb"))
	if err != nil {
		t.Fatal(err)
	}
	LoadFromBytes(data)
	if IPInstance().Reader != current.Reader {
		t.Fatal("LoadFromBytes replaced an initialized reader")
	}
	ReloadIP()
	LoadFromBytes(data)
	if got := IPInstance().LookupCode(net.IPv4(1, 2, 3, 4)); len(got) != 1 || got[0] != "us" {
		t.Fatalf("new memory database country = %v, want [us]", got)
	}
}
