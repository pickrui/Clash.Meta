package auth

import (
	A "github.com/metacubex/mihomo/component/auth"
	"sync"
	"testing"
)

func TestConcurrentAuthenticatorReplacement(t *testing.T) {
	store := NewAuthStore(nil)
	var workers sync.WaitGroup
	for i := 0; i < 4; i++ {
		workers.Go(func() {
			for j := 0; j < 1000; j++ {
				store.SetAuthenticator(A.NewAuthenticator([]A.AuthUser{{User: "local", Pass: "test"}}))
				if current := store.Authenticator(); current != nil && !current.Verify("local", "test") {
					t.Error("partial authentication snapshot")
				}
				store.SetAuthenticator(nil)
			}
		})
	}
	workers.Wait()
}
