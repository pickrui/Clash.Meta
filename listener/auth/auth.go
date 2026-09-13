package auth

import (
	"sync/atomic"

	"github.com/metacubex/mihomo/component/auth"
)

type authenticatorSnapshot struct{ value auth.Authenticator }

type authStore struct {
	snapshot atomic.Pointer[authenticatorSnapshot]
}

func (a *authStore) Authenticator() auth.Authenticator {
	if snapshot := a.snapshot.Load(); snapshot != nil {
		return snapshot.value
	}
	return nil
}

func (a *authStore) SetAuthenticator(authenticator auth.Authenticator) {
	a.snapshot.Store(&authenticatorSnapshot{value: authenticator})
}

func NewAuthStore(authenticator auth.Authenticator) auth.AuthStore {
	store := &authStore{}
	store.SetAuthenticator(authenticator)
	return store
}

var Default auth.AuthStore = NewAuthStore(nil)

type nilAuthStore struct{}

func (a *nilAuthStore) Authenticator() auth.Authenticator {
	return nil
}

func (a *nilAuthStore) SetAuthenticator(authenticator auth.Authenticator) {}

var Nil auth.AuthStore = (*nilAuthStore)(nil) // always return nil, even call SetAuthenticator() with a non-nil authenticator
