package provider

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/profile/cachefile"
	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"
)

func TestProxySubscriptionMetadataConcurrentUpdate(t *testing.T) {
	const childEnv = "MIHOMO_TEST_SUBSCRIPTION_METADATA_CHILD"
	if os.Getenv(childEnv) != "1" {
		command := exec.Command(os.Args[0], "-test.run=^TestProxySubscriptionMetadataConcurrentUpdate$", "-test.count=1")
		command.Env = append(os.Environ(), childEnv+"=1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("isolated subscription metadata: %v\n%s", err, output)
		}
		return
	}
	C.SetHomeDir(t.TempDir())
	defer cachefile.Cache().Close()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("subscription-userinfo", fmt.Sprintf("upload=1; download=%d; total=100; expire=1000", requests.Add(1)))
		_, _ = w.Write([]byte("valid"))
	}))
	defer server.Close()
	provider, err := NewProxySetProvider("test", 0, nil, func([]byte) ([]C.Proxy, error) { return nil, nil }, resource.NewHTTPVehicle(server.URL, filepath.Join(C.Path.HomeDir(), "proxies.yaml"), "", nil, time.Second, 1024), NewHealthCheck(nil, "", 0, 0, true, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	var group sync.WaitGroup
	var finished atomic.Bool
	group.Go(func() {
		defer finished.Store(true)
		for range 30 {
			if err := provider.Update(); err != nil {
				t.Error(err)
			}
		}
	})
	group.Go(func() {
		for !finished.Load() {
			if info := provider.GetSubscriptionInfo(); info != nil && (info.Upload != 1 || info.Total != 100) {
				t.Error("invalid metadata snapshot")
			}
			if _, err := provider.MarshalJSON(); err != nil {
				t.Error(err)
			}
		}
	})
	group.Wait()
	if info := provider.GetSubscriptionInfo(); info == nil || info.Download != 30 {
		t.Fatalf("last metadata was not published: %+v", info)
	}
}
