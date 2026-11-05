package route

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/constant"
)

func controllerTestAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func TestControllerReconfigurationReleasesAllListeners(t *testing.T) {
	address := controllerTestAddress(t)
	cfg := &Config{Addr: address}
	if runtime.GOOS != "windows" {
		directory, err := os.MkdirTemp("", "api-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(directory) })
		cfg.UnixAddr = filepath.Join(directory, "api.sock")
	}
	t.Cleanup(func() { ReCreateServer(&Config{}) })
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 4 {
				ReCreateServer(cfg)
			}
		})
	}
	wg.Wait()
	ReCreateServer(&Config{})
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("stopped controller retained TCP listener: %v", err)
	}
	_ = listener.Close()
	if cfg.UnixAddr != "" {
		listener, err = net.Listen("unix", cfg.UnixAddr)
		if err != nil {
			t.Fatalf("stopped controller retained Unix listener: %v", err)
		}
		_ = listener.Close()
	}
}

func TestControllerReplacementUsesLatestAuthentication(t *testing.T) {
	address := controllerTestAddress(t)
	t.Cleanup(func() { ReCreateServer(&Config{}) })
	for _, secret := range []string{"first", "second", "latest"} {
		ReCreateServer(&Config{Addr: address, Secret: secret})
	}
	client := &http.Client{Timeout: time.Second}
	defer client.CloseIdleConnections()
	for _, tc := range []struct {
		token  string
		status int
	}{
		{"first", http.StatusUnauthorized},
		{"second", http.StatusUnauthorized},
		{"latest", http.StatusOK},
	} {
		request, err := http.NewRequest(http.MethodGet, "http://"+address+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+tc.token)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != tc.status {
			t.Errorf("token %q: status = %d, want %d", tc.token, response.StatusCode, tc.status)
		}
	}
}

func TestControllerTLSValidationFailureReleasesListener(t *testing.T) {
	previousHome := constant.Path.HomeDir()
	constant.SetHomeDir(t.TempDir())
	t.Cleanup(func() { constant.SetHomeDir(previousHome) })
	cert, key, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"client CA", "ECH"} {
		t.Run(name, func(t *testing.T) {
			address := controllerTestAddress(t)
			cfg := &Config{TLSAddr: address, Certificate: cert, PrivateKey: key}
			if name == "client CA" {
				cfg.ClientAuthCert = "missing-controller-ca.pem"
			} else {
				cfg.EchKey = "invalid ECH key"
			}
			startTLS(cfg)
			listener, err := net.Listen("tcp", address)
			if err != nil {
				t.Fatalf("invalid TLS config retained listener: %v", err)
			}
			_ = listener.Close()
		})
	}
}
