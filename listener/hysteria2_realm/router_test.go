package hysteria2_realm

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

func realmRouteRequest(handler http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.RemoteAddr = "127.0.0.1:12345"
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestRealmRouterRejectsInvalidRequests(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, token, body string
		status                          int
		code                            string
	}{
		{"unknown route", "GET", "/unknown", "realm-token", "", 404, errNotFound},
		{"wrong method", "PUT", "/v1/test", "realm-token", "", 405, errBadRequest},
		{"invalid token", "POST", "/v1/test", "wrong", `{}`, 401, errInvalidToken},
		{"invalid realm", "POST", "/v1/bad%20name", "realm-token", `{}`, 400, errBadRequest},
		{"invalid JSON", "POST", "/v1/test", "realm-token", `{`, 400, errBadRequest},
		{"oversized body", "POST", "/v1/test", "realm-token", `{"addresses":["127.0.0.1:443"],"padding":"` + strings.Repeat("x", maxRequestBodyBytes) + `"}`, 400, errBadRequest},
		{"session token required", "POST", "/v1/test/heartbeat", "realm-token", `{}`, 401, errInvalidToken},
		{"invalid nonce", "POST", "/v1/test/connects/invalid", "realm-token", `{}`, 400, errBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newServer(serverConfig{realmToken: "realm-token"})
			response := realmRouteRequest(s.routes(), tc.method, tc.path, tc.token, tc.body)
			var body map[string]string
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if response.Code != tc.status || body["error"] != tc.code {
				t.Fatalf("response changed: status=%d body=%v", response.Code, body)
			}
			if len(s.realms) != 0 {
				t.Fatal("invalid request registered a realm")
			}
		})
	}
}

func TestRealmRouterSessionLifecycle(t *testing.T) {
	s := newServer(serverConfig{realmToken: "realm-token"})
	handler := s.routes()
	response := realmRouteRequest(handler, "POST", "/v1/test", "realm-token", `{"addresses":["127.0.0.1:443"]}`)
	if response.Code != http.StatusOK {
		t.Fatalf("register: %d %s", response.Code, response.Body.String())
	}
	var registration struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &registration); err != nil {
		t.Fatal(err)
	}
	token := registration.SessionID
	if token == "" {
		t.Fatal("missing session token")
	}
	response = realmRouteRequest(handler, "POST", "/v1/other/heartbeat", token, "")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("token crossed realm boundary: %d", response.Code)
	}
	response = realmRouteRequest(handler, "POST", "/v1/test/heartbeat", token, `{"addresses":["[::1]:8443"]}`)
	if response.Code != http.StatusOK {
		t.Fatalf("heartbeat: %d %s", response.Code, response.Body.String())
	}
	sess := s.getSessionByToken(token)
	if sess == nil || len(sess.addresses) != 1 || sess.addresses[0] != "[::1]:8443" {
		t.Fatal("heartbeat did not update addresses")
	}
	response = realmRouteRequest(handler, "POST", "/v1/test/connects/"+strings.Repeat("a", nonceHexLength), token, `{"addresses":["127.0.0.1:443"]}`)
	if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), errAttemptNotFound) {
		t.Fatalf("nested nonce route: %d %s", response.Code, response.Body.String())
	}
	response = realmRouteRequest(handler, "DELETE", "/v1/test", token, "")
	if response.Code != http.StatusNoContent {
		t.Fatalf("deregister: %d", response.Code)
	}
	if len(s.realms) != 0 || len(s.sessions) != 0 || len(s.ipCounts) != 0 {
		t.Fatal("session state remains after deregistration")
	}
	response = realmRouteRequest(handler, "POST", "/v1/test/heartbeat", token, "")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expired token accepted: %d", response.Code)
	}
}
